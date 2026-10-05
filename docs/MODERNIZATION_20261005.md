# Stable modernization, 2026-10-05

The development toolchain is Rust 1.99.0, verified against the official stable
channel manifest and [release announcement](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/).
All packages retain their declared Rust 1.97.1 minimum. The highest resolved
crate MSRV is 1.96.0 (Wasmtime/Cranelift). All 79 unique declared crates were
checked against current stable, non-yanked crates.io releases; both lockfiles
were regenerated and checked for prereleases and yanked versions.

## Direct dependency upgrades

These are changed resolved direct dependencies. Older versions shown include
all versions of that crate in the previous lockfile when transitive users also
selected a different release.

| Crate | Previous locked versions | Latest stable direct version |
| --- | --- | --- |
| `aho-corasick` | 1.1.4 | 1.1.5 |
| `async-trait` | 0.1.91 | 0.1.92 |
| `blake3` | 1.8.6 | 1.8.7 |
| `cfb` | 0.14.0 | 0.15.0 |
| `clap` | 4.6.6 | 4.6.7 |
| `dirs` | 6.0.0 | 7.0.0 |
| `encoding_rs` | 0.8.35 | 0.8.42 |
| `flate2` | 1.1.9 | 1.1.10 |
| `futures-util` | 0.3.33 | 0.3.34 |
| `futures` | 0.3.33 | 0.3.34 |
| `hyper` | 1.11.0 | 1.11.1 |
| `libc` | 0.2.189 | 0.2.190 |
| `log` | 0.4.33 | 0.4.34 |
| `quick-xml` | 0.41.0 | 0.42.0 |
| `rand` | 0.10.2, 0.8.7, 0.9.5 | 0.10.3 |
| `reqwest` | 0.13.4 | 0.13.5 |
| `rmcp` | 3.1.1 | 3.5.0 |
| `rstest` | 0.26.1 | 0.27.0 |
| `test-case` | 3.3.1 | 3.4.0 |
| `thiserror` | 1.0.69, 2.0.20 | 2.0.21 |
| `threatflux-binary-analysis` | 0.2.0 | 0.3.0 |
| `threatflux-cache` | 0.1.8 | 0.2.0 |
| `threatflux-hashing` | 0.1.8 | 1.7.0 |
| `threatflux-string-analysis` | 0.1.1 | 0.2.2 |
| `tokio-test` | 0.4.5 | 0.4.6 |
| `tokio` | 1.53.1 | 1.53.2 |
| `toml` | 1.1.4+spec-1.1.0 | 1.1.6+spec-1.1.0 |
| `tower-http` | 0.6.11, 0.7.0 | 0.7.1 |
| `utoipa-redoc` | 6.0.0 | 7.0.0 |
| `utoipa-swagger-ui` | 9.0.2 | 10.0.1 |
| `utoipa` | 5.5.0 | 6.0.0 |
| `uuid` | 1.24.0 | 1.27.0 |
| `yara-x` | 1.19.0 | 1.21.0 |

## Security patch and compatibility

Published stable YARA-X 1.21.0 still requires vulnerable Wasmtime 45. The
[documented local patch](../vendor/README.md) uses stable Wasmtime 49.0.2 without
changing YARA-X runtime source or enabling additional runtime features. Its
upstream artifact checksum, license, exact manifest patch, and removal condition
are recorded with the vendored dependency. This removes the previous Wasmtime
vulnerability exemptions. The preexisting RSA timing-advisory exemption remains:
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) has no
patched release, including latest stable RSA 0.9.10. YARA-X's sole RSA use is
`RsaPublicKey` and `Pkcs1v15Sign.verify` in `src/modules/utils/crypto.rs`; no
private-key loading, signing, or decryption calls exist in the vendored source.
The advisory concerns private-key leakage. `scripts/check-rsa-exception.py`
checks the reviewed RSA version, sole YARA-X caller, exact public-verification
source hash, and absence of RSA use in other source files before security audits.
The gate fails if these conditions change. A no-ignore audit still reports that
upstream advisory explicitly.
The existing warning-only bincode maintenance exception also remains in
cargo-deny. No new advisory exceptions were added.

The string-analysis upgrade changes upstream DTOs, counts, query validation,
and bounded tracking. The local compatibility wrapper retains the scanner's
existing public fields and JSON shape and adds fallible queries for HTTP error
responses. Legacy classification rules, file-path lists, `200+` length buckets, and
entropy sample thresholds are preserved and checked with migration regressions.
The upgraded statistics count distinct `(path, hash)` identities: scanning changed
content at the same path counts two identities where the previous library counted
one path. Related-string scores use the upstream weighted identity similarity
calculation. Retention and query limits are now bounded. An oversized string does
not prevent later valid strings from being indexed; partial tracking errors are
returned to library callers and logged by MCP. MCP's upstream `ServerInfo` alias was migrated to `ServerConfig`.

The existing threat-detection library now compiles with neither optional engine
or either engine alone. Engine fields and calls follow their feature gates, and
default configuration enables only compiled engines. Tests retain Tokio as a
development dependency without making it a required production dependency.
Production library checks and tests cover all three isolated configurations.

The security override applies to builds from this checkout and its Docker images.
Cargo normalizes published manifests and does not propagate a root `[patch]` to
library consumers. `cargo package --list` also omits the nested vendored crate
source. A published-library consumer therefore needs its own complete top-level
patch or a later fixed published YARA-X release; this change does not claim that
published crate artifacts carry the runtime override. In addition, archive
preparation exposes a preexisting publication mismatch: the local
`threatflux-threat-detection` dependency is version 0.1.0, which has not been
published (the registry offers 0.2.2). Source builds retain the local implementation;
changing that publication strategy is separate from the native modernization.
No crate is published by this modernization.

## Local and hosted checks

`make hooks-install` installs worktree-aware repository hooks and preserves
existing custom hooks. `make ci-local` checks formatting, strict all-target
Clippy, builds, full workspace and standalone package-security tests (including
doctests), feature configurations, strict Rustdoc, benchmark targets, MSRV,
cargo audit, cargo-deny, and every workflow file. It exits on any failed check.
The two timing-sensitive hashing performance tests remain explicitly opt-in;
run them with `cargo test --locked --test hash_test -- --ignored`.

The root workflow validator discovers YAML in all three workflow directories.
It uses actionlint 1.7.12 and yamllint 1.38.0; install those versions and put them
on PATH or set `ACTIONLINT_BIN` / `YAMLLINT_BIN`. Its file discovery also requires
ripgrep, and actionlint uses ShellCheck for embedded shell scripts. The hosted
validator installs both tools explicitly. Rust matrix and MSRV jobs explicitly
select `RUSTUP_TOOLCHAIN` and log compiler versions so the repository pin cannot
override the requested compiler. GitHub Actions and reusable
workflows are pinned to verified immutable upstream commits with version
comments. Cargo security, SBOM, coverage, and cache tools use stable version pins.
The existing auto-release workflow remains the root release owner.

The native MCP smoke test uses a controlled temporary text file, bounded
subprocess execution, and verifies initialization, tool discovery, metadata,
and SHA-256 through the real stdio transport. Run
`python3 scripts/mcp-smoke.py target/debug/file-scanner` after building (adjust
the binary path if `CARGO_TARGET_DIR` is set). It needs no global npm tools.

CI cleanup is restricted to disposable GitHub-hosted Linux runners and preserves
LLVM, Node, CodeQL, Cargo caches, Docker layers, and temporary build inputs.
CI uses two build jobs and disables debug information in development/test builds
to fit hosted runners. Target caches use a `target-debug0-` namespace, and
compiled dependency files are retained between test batches.
Integration failures/timeouts, invalid SBOM output, and failed benchmarks can no
longer be reported as successful checks. Existing optional Semgrep, TruffleHog,
Trivy, and OSV finding policies remain informational; this refresh does not turn
them into new blocking policies. Scan completion/output checks are enforced where
the tools distinguish findings from execution errors.
