# Temporary YARA-X security patch

The root Cargo patch uses the exact published stable YARA-X 1.21.0 source with
stable Wasmtime 49.0.2. Published YARA-X 1.21.0 requires Wasmtime 45.0.3; that
release line has no patch for RUSTSEC-2026-0316 and RUSTSEC-2026-0327, and remains
affected by RUSTSEC-2026-0222 and RUSTSEC-2026-0269. Wasmtime 49.0.2 fixes all
four. No new advisory exemptions are introduced.

## Provenance

- Artifact: [crates.io YARA-X 1.21.0](https://crates.io/api/v1/crates/yara-x/1.21.0/download)
- Artifact SHA-256: `01380fac6a879db2b11b5a3586075ec220988805c98a21497f6895fb35c9d373`
- SHA-256 verified against the crates.io version metadata on 2026-10-05.
- Upstream commit: [`7b2637d4655155fdfaf68177edadb9a39406ece0`](https://github.com/VirusTotal/yara-x/tree/7b2637d4655155fdfaf68177edadb9a39406ece0/lib)
- License: BSD-3-Clause; [LICENSE](yara-x-1.21.0/LICENSE) is copied from that commit.
- Runtime patch: [exact manifest diff](yara-x-1.21.0.patch).

All upstream source, generated module assets, build script and README are
preserved. Upstream Cargo.lock, original workspace Cargo.toml and standalone
benchmark targets/files are omitted because this crate is a dependency of the
root workspace. The normalized manifest changes only the Wasmtime version and
removes the omitted benchmark targets. Existing runtime features remain
`cranelift` and `runtime` with default features disabled. No component model or
WASI support is enabled by this patch. Git whitespace attributes and optional
formatting hooks exempt only the upstream vendor subtree and exact diff context
so checked source bytes and fixture whitespace remain unchanged; application
formatting, compilation, lint, and security gates still apply.

The wrapper compiles against the current native Wasmtime API without runtime
source changes. The application and threat-detection tests exercise real YARA
rule compilation and scanning using this patched dependency. Wasmtime's
minimum supported Rust version is 1.96.0, below this repository's 1.97.1 MSRV.

Remove the root `[patch.crates-io]` entry and this directory when a published
stable YARA-X release resolves a Wasmtime version patched for these advisories.
Regenerate Cargo.lock and rerun the vulnerability audit (including a no-ignore report for the retained RSA exception) and YARA
compile/scan regressions before removing it.

Primary advisory references: [record lifting](https://rustsec.org/advisories/RUSTSEC-2026-0316.html),
[engine type indices](https://rustsec.org/advisories/RUSTSEC-2026-0222.html),
[WASI path escape](https://rustsec.org/advisories/RUSTSEC-2026-0269.html),
[component callback result count](https://rustsec.org/advisories/RUSTSEC-2026-0327.html).

## Distribution scope

This override protects native builds from this repository: the release binaries
and the Docker images. Cargo does not propagate a root `[patch.crates-io]` into
a published crate, and the crate's `include` list leaves out this directory, so
the `threatflux-file-scanner` package on crates.io builds against the upstream
YARA-X 1.21.0 release and its Wasmtime 45.0.3 requirement. `cargo audit` on that
package's lockfile reports the four advisories above. None of them is reachable
from that build:

- RUSTSEC-2026-0316 (dynamic record lifting) and RUSTSEC-2026-0327 (async-lifted
  callback result count) are in Wasmtime's component model. YARA-X enables only
  the `cranelift` and `runtime` features with default features off, so the
  component model is not compiled.
- RUSTSEC-2026-0269 (filesystem sandbox escape) is in `wasmtime-wasi`, which is
  not in the dependency graph.
- RUSTSEC-2026-0222 (type indices mixed between engines) needs an embedder that
  creates two Wasmtime `Engine`s and passes objects between them. YARA-X keeps a
  single process-wide `Engine` and exposes no Wasmtime objects, and this crate
  does not use Wasmtime directly.

So the patch is a security-audit fix, not a behaviour change: the vendored source
differs from the published release only in the Wasmtime requirement (and the
omitted benchmark targets). A library consumer that wants the patched runtime
must add its own complete top-level `[patch.crates-io]` entry or wait for a
published YARA-X release that requires a patched Wasmtime. Use the release
binaries, the Docker image or a source checkout to get this repository's patched
native runtime.
