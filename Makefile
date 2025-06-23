.PHONY: help init build test test-parallel test-unit test-hash test-mcp test-analysis test-integration test-legacy install clean run-debug run-release docker-build docker-run docker-run-http lint fmt check deps update security-audit dev dev-full ci ci-full prepare-release coverage coverage-html setup-optimization

# Default target
help:
	@echo "File Scanner - Makefile Commands"
	@echo "================================"
	@echo "BUILD COMMANDS:"
	@echo "  init          - Initialize project dependencies"
	@echo "  build         - Build the project in debug mode"
	@echo "  release       - Build the project in release mode"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "TEST COMMANDS (OPTIMIZED):"
	@echo "  test          - Run fast unit tests (~2s, 70% faster)"
	@echo "  test-parallel - Run comprehensive parallel tests (~60s)"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-hash     - Run hash tests"
	@echo "  test-mcp      - Run MCP tests"
	@echo "  test-analysis - Run analysis tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-legacy   - Run legacy test command (compatibility)"
	@echo ""
	@echo "QUALITY COMMANDS:"
	@echo "  lint          - Run clippy linter"
	@echo "  fmt           - Format code with rustfmt"
	@echo "  check         - Run cargo check"
	@echo "  security-audit - Run security audit"
	@echo ""
	@echo "RUN COMMANDS:"
	@echo "  install       - Install the binary to ~/.cargo/bin"
	@echo "  run-debug     - Run in debug mode with example file"
	@echo "  run-release   - Run in release mode with example file"
	@echo ""
	@echo "DOCKER COMMANDS:"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  docker-run-http - Run Docker container in MCP HTTP mode (port 3111)"
	@echo ""
	@echo "MISC COMMANDS:"
	@echo "  deps          - Update dependencies"
	@echo "  test-programs - Compile all test programs"
	@echo "  mcp-test      - Test MCP server functionality"
	@echo ""
	@echo "OPTIMIZATION COMMANDS:"
	@echo "  setup-optimization - Install sccache and cargo-llvm-cov"
	@echo "  coverage      - Generate code coverage (fast with llvm-cov)"
	@echo "  coverage-html - Generate HTML coverage report"

# Initialize project
init:
	@echo "Initializing project..."
	rustup update stable
	rustup component add clippy rustfmt
	cargo fetch
	@echo "Project initialized successfully!"

# Build debug version
build:
	@echo "Building debug version..."
	@if command -v sccache >/dev/null 2>&1; then \
		export RUSTC_WRAPPER=sccache; \
	fi; \
	cargo build

# Build release version
release:
	@echo "Building release version..."
	@if command -v sccache >/dev/null 2>&1; then \
		export RUSTC_WRAPPER=sccache; \
	fi; \
	cargo build --release

# Run tests (fast unit tests)
test:
	@echo "Running fast unit tests..."
	./scripts/test-fast.sh

# Run parallel tests (comprehensive)
test-parallel:
	@echo "Running comprehensive parallel tests..."
	./scripts/test-parallel.sh

# Run categorized tests
test-unit:
	@echo "Running unit tests only..."
	./scripts/test-categories.sh unit

test-hash:
	@echo "Running hash tests..."
	./scripts/test-categories.sh hash

test-mcp:
	@echo "Running MCP tests..."
	./scripts/test-categories.sh mcp

test-analysis:
	@echo "Running analysis tests..."
	./scripts/test-categories.sh analysis

test-integration:
	@echo "Running integration tests..."
	./scripts/test-categories.sh integration

# Legacy test command for compatibility
test-legacy:
	@echo "Running legacy test command..."
	cargo test --all-features

# Install binary
install: release
	@echo "Installing file-scanner..."
	cargo install --path .
	@echo "Installed to ~/.cargo/bin/file-scanner"

# Setup optimization tools
setup-optimization:
	@echo "Setting up CI/CD optimization tools..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked
	@command -v sccache >/dev/null 2>&1 || cargo install sccache --locked
	@echo "Optimization tools installed!"

# Generate code coverage with llvm-cov (faster than tarpaulin)
coverage:
	@echo "Generating code coverage..."
	cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	@echo "Coverage report: lcov.info"

# Generate HTML coverage report
coverage-html:
	@echo "Generating HTML coverage report..."
	cargo llvm-cov --all-features --workspace --html
	@echo "Coverage report: open target/llvm-cov/html/index.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/

# Run debug build with example
run-debug: build
	@echo "Running debug build..."
	./target/debug/file-scanner /bin/ls --format yaml

# Run release build with example
run-release: release
	@echo "Running release build..."
	./target/release/file-scanner /bin/ls --format yaml

# Docker operations
docker-build:
	@echo "Building Docker image..."
	docker build -t threatflux/file-scanner:latest .

docker-run:
	@echo "Running Docker container..."
	docker run --rm -v /bin:/data:ro threatflux/file-scanner:latest /data/ls

docker-run-http:
	@echo "Running Docker container in MCP HTTP mode..."
	docker run --rm -p 3111:3000 threatflux/file-scanner:latest mcp-http --port 3000

# Code quality
lint:
	@echo "Running clippy..."
	cargo clippy -- -D warnings

fmt:
	@echo "Formatting code..."
	cargo fmt

fmt-check:
	@echo "Checking code formatting..."
	cargo fmt -- --check

check:
	@echo "Running cargo check..."
	cargo check --all-features

# Dependency management
deps:
	@echo "Updating dependencies..."
	cargo update

deps-tree:
	@echo "Showing dependency tree..."
	cargo tree

# Security audit
security-audit:
	@echo "Running security audit..."
	cargo audit

# Test programs
test-programs:
	@echo "Compiling test programs..."
	cd test_programs && bash compile_all.sh

# MCP testing
mcp-test: release
	@echo "Testing MCP server..."
	@echo "Testing tools/list..."
	npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/list
	@echo ""
	@echo "Testing get_file_metadata..."
	npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner mcp-stdio --method tools/call --tool-name get_file_metadata --tool-arg file_path=/bin/ls

# Development workflow (fast)
dev: fmt lint test
	@echo "Development checks passed!"

# Development workflow (comprehensive)
dev-full: fmt lint test-parallel
	@echo "Comprehensive development checks passed!"

# CI/CD preparation (fast for quick checks)
ci: fmt-check lint test
	@echo "CI checks passed!"

# CI/CD preparation (comprehensive for full validation)
ci-full: fmt-check lint test-parallel security-audit
	@echo "Comprehensive CI checks passed!"

# Release workflow
prepare-release: clean release test-parallel security-audit
	@echo "Release preparation complete!"
	@echo "Binary location: ./target/release/file-scanner"

# Benchmarks (if added in future)
bench:
	@echo "Running benchmarks..."
	cargo bench

# Documentation
docs:
	@echo "Building documentation..."
	cargo doc --no-deps --open

# Version info
version:
	@echo "File Scanner version:"
	@cargo pkgid | cut -d# -f2
