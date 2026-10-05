# Contributing to File Scanner

Thank you for your interest in contributing to File Scanner! We welcome contributions from the community
and are grateful for any help you can provide.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Community](#community)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please read and follow our Code of Conduct:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints and experiences
- Show empathy towards other community members

## Getting Started

1. **Fork the Repository**

   ```bash
   # Fork via GitHub UI, then:
   git clone https://github.com/YOUR_USERNAME/file-scanner.git
   cd file-scanner
   git remote add upstream https://github.com/ThreatFlux/file-scanner.git
   ```

2. **Set Up Development Environment**

   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

   # Install development tools
   rustup component add rustfmt clippy
   cargo install cargo-watch cargo-nextest
   ```

3. **Build and Test**

   ```bash
   cargo build
   cargo test
   cargo clippy
   ```

## How to Contribute

### Ways to Contribute

- 🐛 **Report Bugs**: Open an issue describing the bug
- 💡 **Suggest Features**: Open an issue with your idea
- 📝 **Improve Documentation**: Fix typos, clarify instructions
- 🔧 **Submit Code**: Fix bugs or implement features
- 🧪 **Add Tests**: Improve test coverage
- 👀 **Code Review**: Review pull requests

### Good First Issues

Look for issues labeled:

- `good first issue` - Great for newcomers
- `help wanted` - We need help with these
- `documentation` - Documentation improvements

## Development Setup

### Prerequisites

```bash
# Required
rustc 1.97.1+
cargo 1.97.1+

# Recommended
git 2.0+
make (optional)
```

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Watch mode (auto-rebuild)
cargo watch -x build
```

### Running

```bash
# Run with debug output
RUST_LOG=debug cargo run -- /path/to/file

# Run specific example
cargo run --example basic_scan
```

## Coding Standards

### Rust Style Guide

We follow the official [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/):

```rust
// Good: Use descriptive names
pub fn calculate_file_hash(path: &Path) -> Result<String> {
    // Implementation
}

// Bad: Unclear names
pub fn calc_h(p: &Path) -> Result<String> {
    // Implementation
}
```

### Repository Hooks and Local Checks

Development uses the pinned Rust 1.99.0 toolchain; the supported consumer MSRV
remains 1.97.1. Install the repository hooks before committing:

```bash
make hooks-install
make ci-local
```

The hooks resolve the current worktree and check formatting, staged whitespace,
and conventional commit subjects. Existing custom hooks are preserved. The full
local gate checks both workspace crates and the separately excluded
`threatflux-package-security` crate: formatting, strict linting, build, unit and
integration tests, doctests, feature configurations, strict documentation,
benchmark compilation, MSRV, audit, dependency policy, and all 15 workflow files.
Tests and timeouts propagate failure; no integration failures are suppressed.

Install actionlint 1.7.12 and yamllint 1.38.0 before the workflow gate. Tool paths
can be supplied through `ACTIONLINT_BIN` and `YAMLLINT_BIN`. Cargo audit 0.22.2
and cargo-deny 0.20.2 are the pinned security tools used by CI.

The optional `.pre-commit-config.yaml` adds file validation and extra Rust checks
with the pre-commit framework. Install it with `uv tool install pre-commit`, then
run `pre-commit run --all-files`. Its local Rust hooks use the existing toolchain.

#### Manual Code Quality Checks

If you prefer manual checks:

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Lint with strict warnings (library code)
cargo clippy --lib --bins -- -D warnings

# Lint tests (standard warnings)
cargo clippy --tests -- -W clippy::all

# Security audit
cargo audit
```

### Documentation

- Add doc comments to all public APIs
- Include examples in doc comments
- Keep comments up-to-date with code

```rust
/// Calculates the SHA256 hash of a file.
///
/// # Arguments
/// * `path` - Path to the file
///
/// # Returns
/// * `Ok(String)` - Hex-encoded hash
/// * `Err(Error)` - If file cannot be read
///
/// # Example
/// ```
/// let hash = calculate_sha256("/path/to/file")?;
/// println!("SHA256: {}", hash);
/// ```
pub fn calculate_sha256(path: &Path) -> Result<String> {
    // Implementation
}
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add support for BLAKE3 hashing
fix: correct string extraction for UTF-16
docs: update installation guide for Windows
test: add tests for binary parser
refactor: simplify hash calculation logic
perf: optimize string extraction for large files
chore: update dependencies
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_hash() {
        let path = Path::new("test_data/sample.txt");
        let hash = calculate_sha256(path).unwrap();
        assert_eq!(hash, "expected_hash_value");
    }

    #[test]
    #[should_panic(expected = "file not found")]
    fn test_missing_file() {
        let path = Path::new("nonexistent.txt");
        calculate_sha256(path).unwrap();
    }
}
```

### Test Coverage

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html

# View report
open tarpaulin-report.html
```

## Pull Request Process

1. **Create a Feature Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write code following our standards
   - Add tests for new functionality
   - Update documentation

3. **Test Your Changes**

   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```

4. **Commit Your Changes**

   ```bash
   git add .
   git commit -m "feat: add awesome feature"
   ```

5. **Push to Your Fork**

   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**
   - Go to GitHub and click "New Pull Request"
   - Select your branch
   - Fill out the PR template
   - Link related issues

### PR Requirements

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] New features have tests
- [ ] Documentation is updated
- [ ] Commit messages follow conventions
- [ ] PR description explains changes

### Review Process

1. Automated checks run (tests, linting)
2. Code review by maintainers
3. Address feedback
4. Approval and merge

## Issue Guidelines

### Bug Reports

Please include:

- File Scanner version
- Operating system
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages/logs

**Template:**

```markdown
**Version:** 0.1.0
**OS:** Ubuntu 22.04

**Description:**
Brief description of the bug

**Steps to Reproduce:**
1. Run `file-scanner /path/to/file`
2. ...

**Expected:** What should happen
**Actual:** What actually happens

**Logs:**
```text
Error output here
```

### Feature Requests

Please include:

- Use case description
- Proposed solution
- Alternative solutions
- Additional context

**Template:**

```markdown
**Feature:** Brief title

**Use Case:**
Describe when/why this would be useful

**Proposed Solution:**
How you think it should work

**Alternatives:**
Other ways to solve this

**Additional Context:**
Any other relevant information
```

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:

1. Email <security@threatflux.com>
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

See [SECURITY.md](SECURITY.md) for details.

## Community

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: General questions, ideas
- **Discord**: Real-time chat (coming soon)
- **Email**: <contact@threatflux.com>

### Getting Help

- Check existing issues/discussions
- Read the documentation
- Ask in GitHub Discussions
- Join our Discord server

### Recognition

Contributors are recognized in:

- Release notes
- Contributors file
- Project README

## Development Tips

### Useful Commands

```bash
# Watch tests
cargo watch -x test

# Check before committing
make ci-local

# Generate docs
cargo doc --open

# Update dependencies
cargo update

# Audit dependencies
cargo audit
```

### Performance Testing

```bash
# Profile with flamegraph
cargo flamegraph -- /path/to/large/file

# Benchmark specific function
cargo bench -- hash

# Memory profiling
valgrind --tool=massif target/release/file-scanner /path/to/file
```

### Debugging

```bash
# Debug with lldb
rust-lldb target/debug/file-scanner /path/to/file

# Debug with gdb
rust-gdb target/debug/file-scanner /path/to/file

# Enable debug logging
RUST_LOG=file_scanner=debug cargo run -- /path/to/file
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to File Scanner! 🎉
