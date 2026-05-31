# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches
depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities by creating a
[security advisory](https://github.com/ThreatFlux/file-scanner/security/advisories/new) in this repository.

**Please do not report security vulnerabilities through public GitHub issues.**

If you prefer to submit via email, please send your report to <security@threatflux.com>.

### What to Include

Please include the following details in your report:

- Type of issue (e.g., buffer overflow, path traversal, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 1 week
- **Patch Development**: Varies based on complexity
- **Public Disclosure**: After patch is available

## Security Best Practices

When using file-scanner:

1. **Input Validation**: Always validate file paths before scanning
2. **Resource Limits**: Set appropriate limits for large files
3. **Sandboxing**: Run in containers or VMs when scanning untrusted files
4. **Access Control**: Limit file system access to necessary directories
5. **Updates**: Keep the scanner updated to the latest version

## Security Features

The file-scanner includes several security features:

- Path traversal prevention
- Resource consumption limits
- Safe string extraction
- Memory-safe Rust implementation
- No execution of scanned files

## Dependencies

We regularly update dependencies to patch known vulnerabilities. You can check for outdated dependencies with:

```bash
cargo audit
```

### Temporary Accepted Risk: `yara-x` / `wasmtime`

As of April 30, 2026, the default malware-analysis path still depends on `yara-x`, and the
latest available `yara-x` release continues to resolve to `wasmtime 40.0.4`. The upstream
Wasmtime advisories published on April 9, 2026 are therefore temporarily accepted for this
repository while YARA support remains a core feature.

This exception is limited to the `yara-x` dependency chain and must be re-evaluated when either:

- `yara-x` releases a version that moves to a patched Wasmtime line
- file-scanner makes YARA support optional or isolates it from the default runtime path
- upstream guidance materially changes the exploitability assessment for our supported targets

## Acknowledgments

We appreciate responsible disclosure of security vulnerabilities. Contributors who report valid security
issues will be acknowledged in our releases (unless they prefer to remain anonymous).
