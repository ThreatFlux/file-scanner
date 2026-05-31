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

File Scanner is a comprehensive file analysis tool written in Rust that provides:

- Metadata extraction
- Cryptographic hash calculation
- String extraction and categorization
- Binary format analysis (PE/ELF/Mach-O)
- Digital signature verification
- Advanced malware detection capabilities
- MCP server for AI integration

### How does File Scanner compare to other tools?

| Feature | File Scanner | file | strings | binwalk | YARA |
|---------|--------------|------|---------|---------|------|
| Speed | ⚡ Very Fast | Fast | Fast | Moderate | Fast |
| Hashes | ✅ Multiple | ❌ | ❌ | ❌ | ❌ |
| Strings | ✅ Categorized | ❌ | ✅ Basic | ✅ | ✅ |
| Binary Analysis | ✅ Deep | ✅ Basic | ❌ | ✅ | ❌ |
| Signatures | ✅ | ❌ | ❌ | ❌ | ❌ |
| AI Integration | ✅ MCP | ❌ | ❌ | ❌ | ❌ |
| Memory Safety | ✅ Rust | ✅ | ⚠️ | ⚠️ | ⚠️ |

### Is File Scanner suitable for production use?

Yes! File Scanner is designed for production environments with:

- Comprehensive error handling
- Resource limits and timeouts
- Memory-safe Rust implementation
- Extensive test coverage
- Performance optimizations

### What file types are supported?

File Scanner can analyze any file type, with specialized support for:

- **Executables**: PE (Windows), ELF (Linux), Mach-O (macOS)
- **Archives**: Detection only (no extraction)
- **Documents**: Basic metadata and strings
- **Scripts**: String extraction and pattern detection
- **Any binary**: Hex dumps, entropy analysis, strings

## Installation Issues

### Rust version error

#### Q: I get "error: package requires rustc 1.95.0"

A: Update Rust to the latest version:

```bash
rustup update stable
rustup default stable
```

### Missing dependencies

#### Q: Build fails with "pkg-config not found"

A: Install system dependencies:

```bash
# Ubuntu/Debian
sudo apt-get install pkg-config libssl-dev

# macOS
brew install pkg-config openssl

# Fedora
sudo dnf install pkg-config openssl-devel
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

Use shell scripting or parallel processing:

```bash
# Using find and xargs
find /path -name "*.exe" -print0 | \
  xargs -0 -P 8 -I {} file-scanner {} --format json > results.jsonl

# Using GNU parallel
parallel -j 8 file-scanner {} ::: *.exe

# Using a for loop
for file in *.bin; do
  file-scanner "$file" > "${file}.analysis.txt"
done
```

### Can I scan compressed files?

File Scanner analyzes files as-is without extraction. To scan compressed contents:

```bash
# Extract first, then scan
unzip archive.zip -d temp/
file-scanner temp/* --format json

# For tar archives
tar -tf archive.tar | while read file; do
  tar -xOf archive.tar "$file" | file-scanner -
done
```

### How do I filter output?

Use command-line tools or JSON processors:

```bash
# Extract only hashes
file-scanner file.exe --format json | jq .hashes

# Find suspicious strings
file-scanner file.exe --strings --format json | \
  jq '.strings[] | select(.category == "suspicious")'

# Get files over 10MB
find . -type f -exec file-scanner {} --format json \; | \
  jq 'select(.metadata.file_size > 10485760)'
```

## Performance Questions

### Why is scanning slow?

Common causes and solutions:

1. **Large files**: Use `--fast` mode or selective analysis
2. **Many small files**: Enable parallel processing
3. **Network drives**: Copy files locally first
4. **Signature verification**: Skip with `--no-signatures`

### How can I speed up batch processing?

```bash
# Use parallel processing
export RAYON_NUM_THREADS=8

# Enable memory mapping
export FILE_SCANNER_USE_MMAP=true

# Limit analysis features
file-scanner *.exe --metadata --hashes --no-strings

# Use caching for repeated scans
file-scanner --enable-cache *.bin
```

### Memory usage is too high

Configure memory limits:

```bash
# Set global memory limit
export FILE_SCANNER_MAX_MEMORY=536870912  # 512MB

# Limit string extraction
file-scanner large.bin --strings --max-strings 1000

# Use streaming mode for large files
file-scanner huge.iso --stream-mode
```

## MCP Integration

### MCP server won't start

#### Q: "Address already in use" error

A: Another process is using the port:

```bash
# Find process using port
lsof -i :3000
# or
netstat -tlnp | grep 3000

# Kill the process or use different port
file-scanner mcp-http --port 3001
```

### Claude Code can't find file-scanner

#### Q: "Command not found" in Claude Code

A: Use absolute path in configuration:

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "/usr/local/bin/file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

### MCP tools not showing up

Check MCP server status:

```bash
# Test with inspector
npx @modelcontextprotocol/inspector file-scanner mcp-stdio

# Check tool listing manually
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  file-scanner mcp-stdio
```

## Security Concerns

### Is it safe to scan untrusted files?

Yes, with precautions:

- File Scanner never executes scanned files
- Use resource limits for untrusted files
- Run in a container or VM for isolation
- Set appropriate timeouts

```bash
# Safe scanning setup
docker run --rm -v /suspicious:/data:ro \
  --memory=1g --cpus=1 \
  file-scanner /data/malware.exe
```

### Can File Scanner detect all malware?

File Scanner provides indicators but is not a complete antivirus:

- ✅ Detects suspicious patterns and strings
- ✅ Identifies packed/encrypted sections
- ✅ Finds known malicious APIs
- ❌ No signature database
- ❌ No behavioral sandbox
- ❌ No real-time protection

Use alongside traditional AV tools.

### What about privacy?

File Scanner:

- ✅ Runs completely offline
- ✅ No telemetry or data collection
- ✅ No network connections (except MCP server mode)
- ✅ Open source and auditable

## Troubleshooting

### "Permission denied" errors

```bash
# Check file permissions
ls -la file.bin

# Run with appropriate permissions
sudo file-scanner /root/file.bin

# Or change ownership
sudo chown $USER:$USER file.bin
```

### "File not found" but file exists

Common causes:

- Relative vs absolute paths
- Symbolic links
- Special characters in filename

```bash
# Use absolute path
file-scanner "$(pwd)/file name with spaces.exe"

# Check if it's a symlink
file-scanner "$(readlink -f symlink)"
```

### Incomplete or corrupted output

```bash
# Increase timeout for large files
file-scanner large.bin --timeout 300

# Check disk space
df -h

# Verify file integrity
file-scanner file.bin --verify-first
```

### High CPU usage

```bash
# Limit thread count
export RAYON_NUM_THREADS=2

# Add rate limiting
file-scanner *.bin --rate-limit 100ms

# Use nice to lower priority
nice -n 19 file-scanner large.iso
```

## Development

### How do I add a new analysis module?

1. Create module in `src/analyzers/`
2. Implement the `Analyzer` trait
3. Register in `src/main.rs`
4. Add tests in `tests/`
5. Update documentation

Example:

```rust
pub struct MyAnalyzer;

impl Analyzer for MyAnalyzer {
    type Output = MyAnalysis;

    async fn analyze(&self, data: &[u8]) -> Result<Self::Output> {
        // Implementation
    }
}
```

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Where can I get help?

- 📖 [Documentation](https://github.com/ThreatFlux/file-scanner/tree/main/docs)
- 💬 [GitHub Discussions](https://github.com/ThreatFlux/file-scanner/discussions)
- 🐛 [Issue Tracker](https://github.com/ThreatFlux/file-scanner/issues)
- 📧 Email: <support@threatflux.com>
- 💬 Discord: Coming soon!

## Still have questions?

If your question isn't answered here:

1. Check the [full documentation](https://github.com/ThreatFlux/file-scanner/tree/main/docs)
2. Search [existing issues](https://github.com/ThreatFlux/file-scanner/issues)
3. Ask in [GitHub Discussions](https://github.com/ThreatFlux/file-scanner/discussions)
4. Open a [new issue](https://github.com/ThreatFlux/file-scanner/issues/new)
