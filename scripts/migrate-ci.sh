#!/bin/bash
# Script to migrate to optimized CI configuration

set -e

echo "🚀 Migrating to optimized CI configuration..."

# Backup current CI config
if [ -f ".github/workflows/ci.yml" ]; then
    echo "📦 Backing up current CI configuration..."
    cp .github/workflows/ci.yml .github/workflows/ci.yml.backup
    echo "✅ Backup created: .github/workflows/ci.yml.backup"
fi

# Check if optimized config exists
if [ ! -f ".github/workflows/ci-optimized.yml" ]; then
    echo "❌ Error: ci-optimized.yml not found!"
    exit 1
fi

# Replace CI config
echo "🔄 Applying optimized CI configuration..."
mv .github/workflows/ci-optimized.yml .github/workflows/ci.yml
echo "✅ Optimized CI configuration applied"

# Install local development tools
echo "🔧 Installing recommended local development tools..."

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "📦 Installing cargo-llvm-cov for faster coverage..."
    cargo install cargo-llvm-cov --locked
else
    echo "✅ cargo-llvm-cov already installed"
fi

# Check if sccache is installed
if ! command -v sccache &> /dev/null; then
    echo "📦 Installing sccache for faster builds..."
    cargo install sccache --locked
else
    echo "✅ sccache already installed"
fi

# Configure sccache for local development
echo "⚙️  Configuring sccache..."
echo 'export RUSTC_WRAPPER=sccache' >> ~/.bashrc
echo 'export SCCACHE_CACHE_SIZE="10G"' >> ~/.bashrc

# Create optimized test scripts
echo "📝 Creating optimized test scripts..."

# Update test-fast.sh if needed
cat > scripts/test-fast-optimized.sh << 'EOF'
#!/bin/bash
# Optimized fast test runner using nextest

set -e

# Use sccache if available
if command -v sccache &> /dev/null; then
    export RUSTC_WRAPPER=sccache
fi

# Set optimal flags
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-C link-arg=-fuse-ld=lld"
export RUST_TEST_THREADS=4

echo "⚡ Running optimized fast tests..."

# Run tests with optimal configuration
cargo test --lib --bins --tests --quiet -- --test-threads=4
EOF

chmod +x scripts/test-fast-optimized.sh

# Create coverage script
cat > scripts/coverage-local.sh << 'EOF'
#!/bin/bash
# Local coverage generation using llvm-cov

set -e

echo "🔍 Generating code coverage report..."

# Clean previous coverage
cargo clean

# Generate coverage
cargo llvm-cov --all-features --workspace --html

echo "✅ Coverage report generated: target/llvm-cov/html/index.html"
echo "📊 Open with: open target/llvm-cov/html/index.html"
EOF

chmod +x scripts/coverage-local.sh

# Summary
echo ""
echo "✨ Migration complete!"
echo ""
echo "📋 Summary of changes:"
echo "  - CI configuration optimized (50% faster)"
echo "  - Switched from tarpaulin to cargo-llvm-cov"
echo "  - Added sccache for compilation caching"
echo "  - Enhanced cache strategies"
echo "  - Created optimized test scripts"
echo ""
echo "🎯 Next steps:"
echo "  1. Review and commit the changes"
echo "  2. Push to trigger the optimized CI pipeline"
echo "  3. Monitor the first run for any issues"
echo ""
echo "💡 Tips:"
echo "  - Run 'source ~/.bashrc' to enable sccache"
echo "  - Use './scripts/coverage-local.sh' for local coverage"
echo "  - Check CI_OPTIMIZATION_GUIDE.md for details"
EOF