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

[Unreleased]: https://github.com/vtriple/file-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vtriple/file-scanner/releases/tag/v0.1.0
