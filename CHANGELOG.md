# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Explicitly excluded `threatflux-package-security` from the root workspace so it can be updated and validated independently
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
