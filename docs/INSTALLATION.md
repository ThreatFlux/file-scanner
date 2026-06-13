# Installation Guide

This guide covers installing File Scanner on various platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building from Source](#building-from-source)
- [Docker Installation](#docker-installation)
- [Platform-Specific Instructions](#platform-specific-instructions)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Windows](#windows)
- [Optional Dependencies](#optional-dependencies)
- [Verifying Installation](#verifying-installation)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required

- **Rust**: Version 1.96.0 or later

  ```bash
  # Install Rust via rustup
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

  # Verify installation
  rustc --version
  cargo --version
  ```

### Recommended

- **Git**: For cloning the repository
- **Make**: For using the Makefile (optional)
- **pkg-config**: For linking system libraries

## Building from Source

### Standard Build

```bash
# Clone the repository
git clone https://github.com/ThreatFlux/file-scanner.git
cd file-scanner

# Build in release mode (optimized)
cargo build --release

# The binary will be at: ./target/release/file-scanner
```

### Development Build

```bash
# Build with debug symbols
cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- /path/to/file
```

### Using Make

```bash
# Build release version
make build

# Run tests
make test

# Install to system
make install

# Clean build artifacts
make clean
```

## Docker Installation

### Using Pre-built Image (Coming Soon)

```bash
docker pull ghcr.io/threatflux/file-scanner:latest
```

### Building Docker Image

```bash
# Build the image
docker build -t file-scanner .

# Run with volume mount
docker run -v /path/to/files:/data file-scanner /data/file.bin

# Interactive mode
docker run -it -v /path/to/files:/data file-scanner bash
```

### Docker Compose

```yaml
version: '3.8'
services:
  file-scanner:
    build: .
    volumes:
      - ./samples:/data
    command: ["/data/sample.exe", "--format", "json"]
```

## Platform-Specific Instructions

### Linux

#### Ubuntu/Debian

```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

# Optional: Install signature verification tools
sudo apt-get install -y osslsigncode gpg

# Build File Scanner
cargo build --release
```

#### Fedora/RHEL/CentOS

```bash
# Install build dependencies
sudo dnf install -y gcc pkg-config openssl-devel

# Optional: Install signature verification tools
sudo dnf install -y osslsigncode gnupg2

# Build File Scanner
cargo build --release
```

#### Arch Linux

```bash
# Install build dependencies
sudo pacman -S base-devel pkg-config openssl

# Optional: Install from AUR (coming soon)
# yay -S file-scanner

# Build File Scanner
cargo build --release
```

### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install pkg-config openssl

# Optional: Install signature verification tools
brew install osslsigncode gnupg

# Build File Scanner
cargo build --release

# Note: On Apple Silicon Macs
# Ensure you're using native ARM64 Rust toolchain
rustup default stable-aarch64-apple-darwin
```

### Windows

#### Using PowerShell

```powershell
# Install Rust (if not installed)
# Download and run: https://win.rustup.rs/

# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/

# Clone and build
git clone https://github.com/ThreatFlux/file-scanner.git
cd file-scanner
cargo build --release

# Binary location: .\target\release\file-scanner.exe
```

#### Using WSL2

```bash
# Inside WSL2, follow Linux instructions
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
cargo build --release
```

## Optional Dependencies

### Signature Verification Tools

- **osslsigncode**: For Authenticode signature verification

  ```bash
  # Linux
  sudo apt-get install osslsigncode

  # macOS
  brew install osslsigncode
  ```

- **GPG**: For GPG signature verification

  ```bash
  # Linux
  sudo apt-get install gpg

  # macOS
  brew install gnupg
  ```

- **codesign**: For macOS signature verification (macOS only)
  - Included with Xcode Command Line Tools

### Test Program Compilers

To compile the test programs:

```bash
# C/C++ compilers
sudo apt-get install gcc g++

# Go
sudo apt-get install golang

# Rust (already installed)

# Nim
curl https://nim-lang.org/choosenim/init.sh -sSf | sh

# D Language
sudo apt-get install gdc-13

# Fortran
sudo apt-get install gfortran

# Pascal
sudo apt-get install fpc

# Ada
sudo apt-get install gnat
```

## Verifying Installation

### Basic Test

```bash
# Check version
./target/release/file-scanner --version

# Run help
./target/release/file-scanner --help

# Test on a system file
./target/release/file-scanner /bin/ls
```

### MCP Server Test

```bash
# Test STDIO transport
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  ./target/release/file-scanner mcp-stdio

# Test with MCP Inspector
npm install -g @modelcontextprotocol/inspector
mcp-inspector ./target/release/file-scanner mcp-stdio
```

## Troubleshooting

### Common Issues

#### Rust Version Too Old

```bash
# Update Rust
rustup update stable
rustup default stable
```

#### Missing OpenSSL

```bash
# Linux
sudo apt-get install libssl-dev

# macOS
brew install openssl
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
```

#### Permission Denied

```bash
# Make binary executable
chmod +x ./target/release/file-scanner

# Or install to PATH
sudo cp ./target/release/file-scanner /usr/local/bin/
```

#### Out of Memory During Build

```bash
# Limit parallel jobs
cargo build --release -j 2

# Or increase swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Getting Help

- Check [GitHub Issues](https://github.com/ThreatFlux/file-scanner/issues)
- Join our [Discord Community](https://discord.gg/threatflux)
- Email: <support@threatflux.com>

## Next Steps

- Read the [Usage Guide](USAGE.md) to learn how to use File Scanner
- Check out [MCP Integration](MCP.md) for AI tool integration
- See [Architecture](ARCHITECTURE.md) to understand the codebase
