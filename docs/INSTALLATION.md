# Installation Guide

This guide covers installing File Scanner on various platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installing from crates.io](#installing-from-cratesio)
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

- **Rust**: Version 1.97.1 or later (development toolchain: 1.100.0)

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
- **C compiler**: Some dependencies compile C code (pkg-config and OpenSSL are not needed)

## Installing from crates.io

The crate is published as `threatflux-file-scanner` (the `file-scanner` name on
crates.io belongs to an unrelated crate) and installs the `file-scanner` binary:

```bash
cargo install threatflux-file-scanner --locked
```

Until [crates.io](https://crates.io/crates/threatflux-file-scanner) lists a
release, build from source or download a binary from
[GitHub Releases](https://github.com/ThreatFlux/file-scanner/releases). The
crates.io build uses the upstream YARA-X release; release binaries and container
images carry the vendored YARA-X security patch described in
[vendor/README.md](../vendor/README.md).

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

# Run on a file
cargo run -- /path/to/file
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

### Using Pre-built Image

```bash
docker pull ghcr.io/threatflux/file-scanner:latest

# Scan a file from a read-only mount
docker run --rm -v /path/to/files:/data:ro ghcr.io/threatflux/file-scanner:latest /data/file.bin --format json
```

To run the MCP server from the image (which needs the files mounted at a path the client knows), see
[MCP.md](MCP.md#docker).

### Building Docker Image

```bash
# Build the image
docker build -t file-scanner .

# Run with volume mount
docker run -v /path/to/files:/data file-scanner /data/file.bin

# The runtime image has no shell; pass scanner arguments directly
docker run --rm -v /path/to/files:/data:ro file-scanner /data/file.bin --all --format json
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
sudo apt-get install -y build-essential

# Optional: Install signature verification tools
sudo apt-get install -y osslsigncode gpg

# Build File Scanner
cargo build --release
```

#### Fedora/RHEL/CentOS

```bash
# Install build dependencies
sudo dnf install -y gcc

# Optional: Install signature verification tools
sudo dnf install -y osslsigncode gnupg2

# Build File Scanner
cargo build --release
```

#### Arch Linux

```bash
# Install build dependencies
sudo pacman -S base-devel

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
# No extra packages needed (Xcode command line tools suffice)

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
sudo apt-get install -y build-essential
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

The server expects one JSON object per line on stdin and starts with `initialize`:

```bash
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",'
INIT+='"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}'
printf '%s\n' "$INIT" \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ./target/release/file-scanner mcp-stdio 2>/dev/null | jq -c '{id, tools: (.result.tools // [] | length)}'
```

The second line of output should report 17 tools. To connect a client, see [MCP.md](MCP.md#client-setup); the binary
is at `target/release/file-scanner` after a source build and at `~/.cargo/bin/file-scanner` after `cargo install`. Use
the absolute path in client configuration.

## Troubleshooting

### Common Issues

#### Rust Version Too Old

```bash
# Update Rust
rustup update stable
rustup default stable
```

#### A native dependency fails to compile

Install a C compiler (`build-essential` on Debian and Ubuntu, `gcc` on Fedora, Xcode command line tools on macOS).
OpenSSL and pkg-config are not needed.

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
- Read the [MCP guide](MCP.md) to use the scanner from Claude Code, Claude Desktop, Cursor or VS Code
- See [Architecture](ARCHITECTURE.md) to understand the codebase
