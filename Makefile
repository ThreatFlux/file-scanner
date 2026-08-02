CARGO ?= cargo
RUST_MSRV ?= 1.97.1
RUST_TOOLCHAIN ?= 1.97.1
BINARY_NAME ?= file-scanner
BINARY_PACKAGE ?= file-scanner
SBOM_MANIFEST_PATH ?= Cargo.toml
DOCKER_IMAGE ?= threatflux/file-scanner
DOCKER_TAG ?= latest

# Define all ThreatFlux libraries
LIBRARIES := threatflux-hashing threatflux-string-analysis threatflux-cache threatflux-binary-analysis threatflux-threat-detection threatflux-package-security

.PHONY: all help init build test test-parallel test-unit test-hash test-mcp test-analysis test-integration test-legacy install clean run-debug run-release docker-build docker-run docker-run-http lint fmt check deps update security-audit dev dev-full ci ci-full prepare-release coverage coverage-html setup-optimization libs-% parallel-% \
         fmt-check test-no-features test-mcp-features build-examples test-doc doc-check doc-links \
         deny outdated security-geiger security-supply-chain semver-check feature-test feature-test-full \
         msrv msrv-install security-enhanced ci-local validate analyze examples release-prep docs

# Default target
all: setup-optimization fmt lint build test security-audit
	@echo "✅ All checks passed!"

# CI simulation - matches GitHub Actions CI workflow
ci-local: fmt-check lint build test test-mcp security-audit
	@echo "✅ CI checks passed!"

# Full validation (everything)
validate: all coverage test-parallel libs-test
	@echo "🎉 Full validation complete!"

# Complete analysis (all tools, all checks)
analyze: validate security-enhanced doc-check
	@echo "🎯 Complete analysis finished!"

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
	@echo "  msrv          - Check Rust $(RUST_MSRV) compatibility"
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
	@echo "LIBRARY COMMANDS:"
	@echo "  libs-build    - Build all ThreatFlux libraries"
	@echo "  libs-test     - Test all ThreatFlux libraries"
	@echo "  libs-fmt      - Format all ThreatFlux libraries"
	@echo "  libs-clippy   - Lint all ThreatFlux libraries"
	@echo "  libs-clean    - Clean all ThreatFlux libraries"
	@echo "  parallel-fmt  - Format all libraries in parallel"
	@echo "  parallel-clippy - Lint all libraries in parallel"
	@echo "  parallel-test - Test all libraries in parallel"
	@echo ""
	@echo "INDIVIDUAL LIBRARY COMMANDS:"
	@echo "  <library>-<command> - Run command on specific library"
	@echo "  Available libraries: $(LIBRARIES)"
	@echo "  Available commands: build, test, fmt, clippy, clean"
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
	rustup toolchain install $(RUST_TOOLCHAIN)
	rustup component add --toolchain $(RUST_TOOLCHAIN) clippy rustfmt llvm-tools-preview
	$(CARGO) +$(RUST_TOOLCHAIN) fetch
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

# Test without features
test-no-features:
	@echo "🧪 Running tests without features..."
	@cargo test --no-default-features
	@echo "✅ Tests without features passed"

# Test with MCP features
test-mcp-features:
	@echo "🧪 Testing MCP features..."
	@cargo test --features "mcp"
	@echo "✅ MCP feature tests passed"

# Build examples
build-examples:
	@echo "🔨 Building examples..."
	@if [ -d "examples" ]; then \
		cargo build --examples --all-features; \
	else \
		echo "No examples directory found"; \
	fi
	@echo "✅ Examples built successfully"

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
	docker build \
		--build-arg BINARY_NAME=$(BINARY_NAME) \
		--build-arg BINARY_PACKAGE=$(BINARY_PACKAGE) \
		--build-arg SBOM_MANIFEST_PATH=$(SBOM_MANIFEST_PATH) \
		--build-arg OCI_IMAGE_TITLE="File Scanner" \
		--build-arg OCI_IMAGE_DESCRIPTION="Comprehensive native file scanner with MCP server support" \
		--build-arg OCI_IMAGE_VENDOR=ThreatFlux \
		--build-arg OCI_IMAGE_SOURCE=https://github.com/ThreatFlux/file-scanner \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) .

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
	@echo "🔍 Checking code format..."
	@cargo fmt -- --check
	@echo "✅ Format check passed"

msrv-install:
	@echo "Installing Rust $(RUST_MSRV)..."
	@rustup toolchain install $(RUST_MSRV) --profile minimal
	@rustup component add --toolchain $(RUST_MSRV) clippy rustfmt

msrv: msrv-install
	@echo "Checking MSRV ($(RUST_MSRV))..."
	@rustup run $(RUST_MSRV) cargo check --workspace --all-features
	@echo "✅ MSRV check passed"


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
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	cargo audit

# Additional security checks
deny:
	@echo "🚫 Running cargo-deny checks..."
	@cargo deny check
	@echo "✅ Cargo deny checks passed"

outdated:
	@echo "📊 Checking for outdated dependencies..."
	@cargo outdated || true
	@echo "✅ Outdated check complete"

security-geiger:
	@echo "🔍 Analyzing unsafe code usage..."
	@cargo geiger --output-format GitHubMarkdown > unsafe-report.md || echo "⚠️ Geiger analysis completed with warnings"
	@echo "✅ Unsafe code analysis complete (see unsafe-report.md)"

security-supply-chain:
	@echo "🔗 Analyzing supply chain security..."
	@cargo supply-chain crates > supply-chain-report.txt 2>&1 || echo "⚠️ Supply chain analysis completed with warnings"
	@echo "✅ Supply chain analysis complete (see supply-chain-report.txt)"

security-enhanced: security-audit deny outdated
	@echo "✅ Enhanced security analysis complete!"

# Dependency analysis with cargo-deny
deny-check:
	@echo "Running cargo-deny checks..."
	cargo deny check

# Check for outdated dependencies
outdated-check:
	@echo "Checking for outdated dependencies..."
	cargo outdated

# Remove unused dependencies
machete-check:
	@echo "Checking for unused dependencies..."
	cargo machete

# Full quality check
quality-check: fmt-check lint security-audit deny-check
	@echo "✅ All quality checks passed!"

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

doc-check:
	@echo "📖 Checking documentation..."
	@RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --document-private-items
	@echo "✅ Documentation check passed"

doc-links:
	@echo "🔗 Checking documentation links..."
	@cargo doc --all-features --no-deps --document-private-items
	@echo "✅ Documentation link check complete"

test-doc:
	@echo "📚 Testing documentation examples..."
	@cargo test --doc --all-features
	@echo "✅ Doc tests passed"

# Version info
version:
	@echo "File Scanner version:"
	@cargo pkgid | cut -d# -f2

# Library-specific targets
libs-build:
	@echo "🔨 Building all ThreatFlux libraries..."
	@for lib in $(LIBRARIES); do \
		echo "Building $$lib..."; \
		cd $$lib && make build && cd ..; \
	done

libs-test:
	@echo "🧪 Testing all ThreatFlux libraries..."
	@for lib in $(LIBRARIES); do \
		echo "Testing $$lib..."; \
		cd $$lib && make test && cd ..; \
	done

libs-fmt:
	@echo "🎨 Formatting all ThreatFlux libraries..."
	@for lib in $(LIBRARIES); do \
		echo "Formatting $$lib..."; \
		cd $$lib && make fmt && cd ..; \
	done

libs-clippy:
	@echo "📎 Linting all ThreatFlux libraries..."
	@for lib in $(LIBRARIES); do \
		echo "Linting $$lib..."; \
		cd $$lib && make clippy && cd ..; \
	done

libs-clean:
	@echo "🧹 Cleaning all ThreatFlux libraries..."
	@for lib in $(LIBRARIES); do \
		echo "Cleaning $$lib..."; \
		cd $$lib && make clean && cd ..; \
	done

# Parallel targets for faster execution
parallel-fmt:
	@echo "🎨 Formatting all ThreatFlux libraries in parallel..."
	@echo $(LIBRARIES) | tr ' ' '\n' | xargs -I {} -P 6 sh -c 'cd {} && make fmt'

parallel-clippy:
	@echo "📎 Linting all ThreatFlux libraries in parallel..."
	@echo $(LIBRARIES) | tr ' ' '\n' | xargs -I {} -P 6 sh -c 'cd {} && make clippy'

parallel-test:
	@echo "🧪 Testing all ThreatFlux libraries in parallel..."
	@echo $(LIBRARIES) | tr ' ' '\n' | xargs -I {} -P 6 sh -c 'cd {} && make test'

# Individual library targets
threatflux-hashing-%:
	@cd threatflux-hashing && make $*

threatflux-string-analysis-%:
	@cd threatflux-string-analysis && make $*

threatflux-cache-%:
	@cd threatflux-cache && make $*

threatflux-binary-analysis-%:
	@cd threatflux-binary-analysis && make $*

threatflux-threat-detection-%:
	@cd threatflux-threat-detection && make $*

threatflux-package-security-%:
	@cd threatflux-package-security && make $*
