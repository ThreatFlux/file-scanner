# GitHub Workflows Documentation

This directory contains the workflows that build, test, scan and release File
Scanner. Every workflow starts from read-only `contents: read` permissions and
each job requests only the extra scopes it needs. Every third-party action is
pinned to a full commit SHA with its release tag in a trailing comment, and
`validate.yml` fails on any medium or high [zizmor](https://docs.zizmor.sh)
finding.

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push / pull request to `main` | Formatting, Clippy, tests on Linux and macOS (stable and beta), MSRV, coverage, benchmarks compile, MCP stdio smoke test, Docker build |
| `security.yml` | push / pull request to `main`, daily | cargo-audit, cargo-deny, CodeQL, dependency review, SBOM, TruffleHog, Semgrep |
| `docker.yml` | source changes, `v*` tags, weekly | Builds the distroless image, smoke-tests it, scans it with Trivy, signs and pushes it to GHCR |
| `performance.yml` | push / pull request to `main`, weekly | Criterion benchmarks; `main` results are published to GitHub Pages |
| `validate.yml` | workflow changes | yamllint, actionlint and zizmor |
| `auto-release.yml` | successful CI and Security Audit on `main`, manual | Cuts the next release with the reusable ThreatFlux auto-release workflow |
| `release.yml` | `v*.*.*` tags, manual | Builds release binaries and the SBOM, uploads them to the GitHub Release, and handles crates.io |

## Releasing

Releases are automatic. After CI and Security Audit pass on `main`,
`auto-release.yml` calls `ThreatFlux/github_actions`'s reusable auto-release
workflow. It derives the next version from the conventional commits since the
last tag (`fix:` is a patch, `feat:` a minor release; `ci:`, `build:`,
`chore:`, `docs:` and `test:` do not release), bumps `Cargo.toml`, and creates
the tag and GitHub Release as the `threatflux-automation` GitHub App
(`TF_AUTOMATION_APP_ID` / `TF_AUTOMATION_APP_PRIVATE_KEY`). Because the App
pushes the tag, the tag push itself starts `release.yml` and `docker.yml`.

To rehearse a release without creating anything:

```bash
# What would auto-release do next?
gh workflow run auto-release.yml -f dry_run=true

# Build, package and verify the current main as a release
gh workflow run release.yml --ref main -f version=0.3.5 -f dry_run=true
```

A `release.yml` dry run builds every target, generates the SBOM, verifies the
crates.io package step and builds and smoke-tests the container image; it
creates no tag, release, asset, crate or image.

### Release assets

| Platform | Architecture | Asset |
|----------|-------------|-------|
| Linux | x86_64 | `file-scanner-vX.Y.Z-linux-amd64.tar.gz` |
| Linux | arm64 | `file-scanner-vX.Y.Z-linux-arm64.tar.gz` |
| macOS | Apple Silicon | `file-scanner-vX.Y.Z-macos-arm64.tar.gz` |
| macOS | Intel | `file-scanner-vX.Y.Z-macos-amd64.tar.gz` |
| Windows | x86_64 | `file-scanner-vX.Y.Z-windows-amd64.zip` |
| SBOM | - | `file-scanner-vX.Y.Z.cdx.json` (CycloneDX 1.5) |

Each archive has a `.sha256` checksum beside it. Container images are published
to `ghcr.io/threatflux/file-scanner` by `docker.yml` with semver, `latest` and
commit tags, and are signed with cosign (keyless).

### crates.io

`release.yml` publishes with crates.io trusted publishing: the publish job runs
in the `crates-io` environment and exchanges its OIDC token
(`id-token: write`) for a short-lived token through
`rust-lang/crates-io-auth-action`; no registry secret is stored. Versions that
are already on crates.io are skipped, and a publish failure fails the run.

Publishing is currently disabled with the repository variable
`CRATES_IO_PUBLISH=false`: the `file-scanner` crate name belongs to an
unrelated crate, and the local `threatflux-threat-detection` 0.1.0 path
dependency is not on crates.io. While it is disabled, real releases skip
crates.io and dry runs only check the packaged file list. The local
`threatflux-threat-detection` and `threatflux-package-security` crates and the
vendored YARA-X source set `publish = false` or are not workspace members, and
are never published from this repository.

## Container image

The `Dockerfile` builds on `rust:1.99.0-trixie` and runs on
`gcr.io/distroless/cc-debian13:nonroot` (both pinned by digest) as uid 65532
under `tini`. The runtime has no shell or package manager, so pass scanner
arguments straight to the container:

```bash
docker run --rm -v /path/to/files:/data:ro ghcr.io/threatflux/file-scanner /data/file.bin --format json
```

## Maintenance

Dependabot opens weekly updates for Cargo (root workspace and
`threatflux-package-security`), GitHub Actions and the Dockerfile. When updating
an action by hand, pin the commit SHA that its release tag resolves to and keep
the tag in the trailing comment. Refresh the distroless runtime digest with:

```bash
docker buildx imagetools inspect gcr.io/distroless/cc-debian13:nonroot | awk '/^Digest:/{print $2; exit}'
```
