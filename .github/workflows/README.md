# GitHub Workflows Documentation

This directory contains the workflows that build, test, scan and release File
Scanner. Every workflow starts from read-only `contents: read` permissions and
each job requests only the extra scopes it needs. Every third-party action is
pinned to a full commit SHA with its release tag in a trailing comment, and
`validate.yml` fails on any medium or high [zizmor](https://docs.zizmor.sh)
finding.

## Workflows

- `ci.yml` (push and pull request to `main`): formatting, Clippy, tests on Linux
  and macOS (stable and beta), MSRV, coverage, benchmark compilation, the MCP stdio
  smoke test and a Docker build.
- `security.yml` (push and pull request to `main`, daily): cargo-audit, cargo-deny,
  CodeQL, dependency review, SBOM, TruffleHog and Semgrep.
- `docker.yml` (source changes, `v*` tags, weekly): builds the distroless image,
  smoke-tests it, scans it with Trivy, and signs and pushes it to GHCR.
- `performance.yml` (push and pull request to `main`, weekly): Criterion
  benchmarks; results from `main` are published to GitHub Pages.
- `validate.yml` (workflow changes): yamllint, actionlint and zizmor.
- `auto-release.yml` (successful CI and Security Audit on `main`, manual): cuts the
  next release with the reusable ThreatFlux auto-release workflow.
- `release.yml` (`v*.*.*` tags, manual): builds the release binaries and the SBOM,
  uploads them to the GitHub Release, and handles crates.io.

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

A `release.yml` dry run builds every target, generates the SBOM, runs the
crates.io package check, and builds and smoke-tests the container image locally
on the runner. It creates no tag, release or asset, publishes no crate, and
pushes no image.

### Release assets

| Platform | Architecture | Asset |
| --- | --- | --- |
| Linux | x86_64 | `file-scanner-vX.Y.Z-linux-amd64.tar.gz` |
| Linux | arm64 | `file-scanner-vX.Y.Z-linux-arm64.tar.gz` |
| macOS | Apple Silicon | `file-scanner-vX.Y.Z-macos-arm64.tar.gz` |
| macOS | Intel | `file-scanner-vX.Y.Z-macos-amd64.tar.gz` |
| Windows | x86_64 | `file-scanner-vX.Y.Z-windows-amd64.zip` |
| SBOM | - | `file-scanner-vX.Y.Z.cdx.json` (CycloneDX 1.5) |

Each archive has a `.sha256` checksum beside it. Asset names follow the
`file-scanner` binary, not the `threatflux-file-scanner` crate name, so download
URLs stay the same across releases. Container images are published
to `ghcr.io/threatflux/file-scanner` by `docker.yml` with semver, `latest` and
commit tags, and are signed with cosign (keyless).

### crates.io

`release.yml` publishes with crates.io trusted publishing: the publish job runs
in the `crates-io` environment and exchanges its OIDC token
(`id-token: write`) for a short-lived token through
`rust-lang/crates-io-auth-action`; no registry secret is stored. Versions that
are already on crates.io are skipped, and a publish failure fails the run.

The crate is published as `threatflux-file-scanner`: crates.io treats `-` and
`_` alike, so the unrelated `file_scanner` crate owns the `file-scanner` name.
The binary stays `file-scanner` and the library stays `file_scanner`. The
package `include` list ships only `src/`, the manifest, `Cargo.lock`, the README,
the changelog and the license. The standalone `threatflux-package-security`
crate and the vendored YARA-X source are never published from this repository,
and the published crate builds against the upstream YARA-X release (see
[vendor/README.md](../../vendor/README.md#distribution-scope)).

Publishing from the workflow is disabled with the repository variable
`CRATES_IO_PUBLISH=false` until the first version is on crates.io: trusted
publishing cannot create a new crate. While it is disabled, real releases skip
crates.io; dry runs still run `cargo publish --dry-run` on the package.

#### First publish (one time)

A maintainer publishes the first version by hand from a release tag, with a
short-lived API token:

1. On crates.io, create an API token under Account Settings > API Tokens with
   the `publish-new` scope, restricted to the `threatflux-file-scanner` crate
   name, with the shortest expiry available.
2. Publish from a clean checkout of the release tag:

   ```bash
   git clone --depth 1 --branch vX.Y.Z https://github.com/ThreatFlux/file-scanner /tmp/threatflux-file-scanner-publish
   cd /tmp/threatflux-file-scanner-publish
   cargo login            # paste the token when prompted
   cargo publish --locked -p threatflux-file-scanner
   cargo logout
   ```

3. Revoke the token on crates.io.

Then switch the repository to trusted publishing:

1. On the crate's crates.io Settings > Trusted Publishing page, add a GitHub
   publisher: owner `ThreatFlux`, repository `file-scanner`, workflow
   `release.yml`, environment `crates-io`.
2. Delete the `CRATES_IO_PUBLISH` repository variable
   (`gh variable delete CRATES_IO_PUBLISH -R ThreatFlux/file-scanner`), so the
   next release publishes through `release.yml`.
3. On the same crates.io settings page, turn on "Require trusted publishing"
   so API tokens can no longer publish the crate.

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
