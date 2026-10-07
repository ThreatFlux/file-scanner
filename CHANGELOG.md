# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Explicitly excluded `threatflux-package-security` from the root workspace so it can be updated and validated independently
- Added Dependabot coverage for the standalone `threatflux-package-security` crate
- Added `release.yml`: release binaries for Linux (x86_64, arm64), macOS (arm64,
  x86_64) and Windows with checksums and a CycloneDX SBOM, a `dry_run` mode, and
  crates.io trusted publishing (OIDC) gated by the `CRATES_IO_PUBLISH` variable
- Auto-release cuts releases as the `threatflux-automation` GitHub App, whose tag
  push starts `release.yml` and `docker.yml`, and supports `dry_run`
- Moved the container runtime to distroless Debian 13
  (`gcr.io/distroless/cc-debian13:nonroot`) running as uid 65532 under `tini`
- Hardened workflows: read-only default permissions, no persisted checkout
  credentials, Codecov uploads via OIDC instead of a token, and a zizmor audit in
  workflow validation
- Marked the local `threatflux-threat-detection` and `threatflux-package-security`
  crates `publish = false` and removed their inert workflow copies, which
  referenced retired registry credentials

### Fixed

- The Windows release checksum (`*-windows-amd64.zip.sha256`) ended in CRLF, which macOS
  `shasum -a 256 -c` and `sha256sum -c` cannot read; it now ends in LF like the other
  checksums, and the release job refuses to publish a checksum file in any other format
- The Docker workflow no longer prunes untagged GHCR versions on `main`: they include the
  per-platform images of every multi-arch tag, so released tags such as `0.3.5` lost their
  `linux/amd64` and `linux/arm64` images and could no longer be pulled
- String extraction compiled its twelve categorization regexes for every extracted string
  (about 2.6 ms per string); they are now compiled once, so 1,000 strings take about
  0.6 ms instead of 2.6 s and the `main` benchmark run finishes within its timeout
- Threat-detection tests no longer require a nonzero duration from an engine-less
  scan, which can finish within one clock tick on macOS
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

[Unreleased]: https://github.com/vtriple/file-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vtriple/file-scanner/releases/tag/v0.1.0
