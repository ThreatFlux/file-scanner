# Security alert remediation — 2026-10-21

The user authorized fixing the confirmed findings and dismissing false positives.
All 27 previously open alerts were checked again. **16 false positives are now
dismissed in GitHub: 13 code-scanning alerts and 3 Dependabot alerts.** The
remaining 11 affected-component findings have runtime fixes in this branch;
their default-branch alert state changes after the fixes are merged, published
and scanned on `main`.

## Completed false-positive dispositions

The verified [API disposition record](alert-dispositions-2026-10-21.json)
contains the exact comments, timestamps and alert URLs. The
[final code-scanning triage](code-scanning-final-triage-2026-10-21.md) contains
the underlying source, disassembly and both-platform inventory evidence.

- Code-scanning **257, 258, 269, 270, 276, 277, 278, 280, 281, 289, 290, 316,
  317**: dismissed as `false positive`. Both immutable published amd64 and arm64
  images were examined. This includes source-package fanout, an unsupported
  PowerPC-only implementation, absent privileged/nscd prerequisites, a
  header-only C++ flaw, POSIX aligned allocation proven by disassembly, and an
  exact zlib source version preceding the vulnerable feature.
- Dependabot **65, 67, 68**: dismissed as `not_used`. Morgan is upstream Express
  fixture metadata parsed as data, excluded from the published Rust package and
  runtime image, and never installed or executed by the scanner. These remain
  accurate vulnerable-version matches; the dismissal describes actual nonuse.

The bounded comments identify assumptions that require re-review if targets,
privileged configuration, native consumers or fixture execution change. No
blanket vulnerability ignore was added.

## Implemented fixes for every retained TP

| Alerts | Affected component | Implemented fix |
|---|---|---|
| [22](https://github.com/ThreatFlux/file-scanner/security/code-scanning/22), [25](https://github.com/ThreatFlux/file-scanner/security/code-scanning/25), [187](https://github.com/ThreatFlux/file-scanner/security/code-scanning/187), [189](https://github.com/ThreatFlux/file-scanner/security/code-scanning/189), [194](https://github.com/ThreatFlux/file-scanner/security/code-scanning/194), [204](https://github.com/ThreatFlux/file-scanner/security/code-scanning/204), [205](https://github.com/ThreatFlux/file-scanner/security/code-scanning/205), [206](https://github.com/ThreatFlux/file-scanner/security/code-scanning/206), [207](https://github.com/ThreatFlux/file-scanner/security/code-scanning/207), [266](https://github.com/ThreatFlux/file-scanner/security/code-scanning/266) | Debian glibc 2.41, including the evidenced `getaddrinfo` path | Replace the vulnerable runtime with pinned Wolfi glibc **2.44-r8**. Preserve the GNU ABI, nonroot user, CA roots, tini and application features. |
| [124](https://github.com/ThreatFlux/file-scanner/security/code-scanning/124) | Old runtime zlib 1.3.1 CRC implementation | Remove the unused runtime zlib package. Explicitly build the patched bundled zlib **1.3.2** through locked `libz-sys` 1.1.31 (updated 2026-10-31), so the builder's older system zlib cannot be linked accidentally. |

The [official minimal glibc runtime](https://images.chainguard.dev/directory/image/glibc-dynamic/overview)
is pinned by multi-architecture index:
`sha256:3f1283dc2a6a48c25cd2e1c7730a871b19b721975240e108e0d6a73b555a3a20`.

| Platform | Immutable runtime manifest |
|---|---|
| amd64 | `sha256:c83b6b675bf7c81966a4dad05264a69eec44932a8d1c26c948e862e3d97d5d36` |
| arm64 | `sha256:bd427f34b883443b4a243705a040eeec1b8fb53e473f1b0c4abd8535d661ee0c` |

Both actual package inventories contain glibc/loader 2.44-r8, libgcc/libstdc++
16.2.0-r1, CA roots and Wolfi baselayout. Neither contains zlib. The Rust builder
stays Debian 13 on Rust 1.99.1; the runtime migration preserves existing GNU
behavior rather than changing the application to musl.

## Independent glibc source and advisory verification

A clean result after changing distributions was cross-checked against the
[exact Wolfi source revision](glibc-source-fix-verification-2026-10-21.md),
not inferred from an absent finding. All ten glibc fixes are present: six
complete official patches reverse-apply exactly without fuzz or offsets; four
additional fixed implementations and registered upstream regression tests
were inspected. The full glibc test suite was not built or run during review.
The [DNS-specific proof](glibc-dns-fix-proof-2026-10-21.md) also corrects
reachability: CVE-2026-5435/6238 concern deprecated DNS printing/debugging
functions, so ordinary DNS resolution alone does not prove their execution.
Their source fixes are included regardless.

[Primary Chainguard advisory snapshots](evidence/glibc/summary.json) separately
map both architectures to fixed package versions for six findings:
CVE-2026-19542 at 2.44-r1; CVE-2026-77117/80489/19499 at 2.44-r4;
CVE-2026-18374 at 2.44-r6; CVE-2026-8674 at 2.44-r8. All are satisfied by
the pinned 2.44-r8 runtime. Verbatim upstream patches, advisory source URLs
and checksums are retained under `evidence/glibc/`.

## Native zlib fix beyond package scan coverage

Independent review caught that bundled zlib 1.3.2 fixes the CRC issue but also
contains the later vulnerable nonblocking gzip implementation involved in
CVE-2026-85091. The old runtime's 1.3.1 finding was a version-range FP; introducing
1.3.2 without a source fix would be a different exposure.

The [vendored libz-sys patch](../../vendor/libz-sys-1.1.31.patch) applies the exact
[upstream fix](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148).
It restores owned-buffer/input state when a large nonblocking gzip write stalls.
The stable wrapper and zlib version identifiers are preserved; the actual C
source changes. Official crate checksum, upstream commit, licenses, exact diff
and source hash are documented in [vendor provenance](../../vendor/README.md).

- The native AddressSanitizer regression passes against the patched actual C
  sources. The same regression fails against the pristine official crate,
  proving that it detects the missing fix.
- `make native-zlib-check` checks the root patch/lock resolution, reviewed
  manifest/build/header/CRC/gzip source fingerprints and static production build
  selection, then runs that native regression.
- Both CI audit jobs and the local security gate run these checks. This catches
  the native source issue that an otherwise clean package scan missed.

Root Cargo overrides protect repository source builds, release binaries and
containers when the reviewed native build selection applies. Downstream
crates.io consumers must provide their own top-level overrides; root patches
are not inherited by published library consumers.

## Scan and functional evidence

The [evidence manifest](evidence/manifest.json) records hashes and exact image
identity. Full Trivy JSON and the final Cargo SBOM are preserved compressed in
`evidence/`; the JSON inventory is retained, not reduced to a green summary.

- Trivy **0.76.0**, fresh database updated **2026-10-21 01:19:53 UTC**, all
  severities `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL`, OS and library scanning, no
  ignore file: both immutable runtime platforms report **zero vulnerabilities**.
- The exact assembled **arm64 release** candidate, including the native source
  fix, reports **zero vulnerabilities across 7 OS packages and 451 Cargo
  packages**. Its config ID is
  `sha256:fc46778ea9793502d895b44ec6fc7f4453884e5088fd946fcbd372002d3019e5`.
- Production ELF imports only libc, libm and libgcc; it imports no libz. The
  native patched implementation is selected explicitly during compilation.
- CLI text/JAR/wheel/tar.gz metadata and hashes, compressed archive analysis,
  MCP stdio initialization/tool listing/file analysis, and HTTP MCP health and
  tool execution pass in the actual runtime.
- The application's actual `RepositoryIntegrityChecker` successfully reaches
  npm and PyPI using its locked Reqwest/Rustls implementation, normal CA
  verification and the new runtime's DNS resolver.
- The final amd64 assembled image is a required PR Docker build/scan result;
  the immutable amd64 runtime base has independently passed its full scan. See
  the PR validation notes for the exact final amd64 build result.

## Preventing incomplete or misleading future scans

The Docker workflow now scans all severities, preserves JSON/SARIF and database
metadata, uploads full findings, and fails on any reported vulnerability.
Published amd64 and arm64 images are selected remotely by the **build's immutable
index digest**. PR scans validate the loaded artifact's config ID. The validator
also requires the correct architecture, a supported OS inventory, the scanner's
source label and its populated Cargo SBOM inventory. A clean base image or an
empty report cannot pass as the application image.

Twelve regression tests cover wrong architecture/identity, mutable references,
missing application/OS/package inventory, malformed findings and every severity.
The existing `.github/workflows/docker.yml:scan` SARIF category is preserved for
amd64 so a clean default-branch scan resolves the existing alerts. Arm64 has its
own additional category. Full evidence is uploaded before the vulnerability
gate fails; findings are not hidden to make a check green.

## Default-branch completion

The 11 TP alerts remain open on the older published `main` image until this
change is merged and the Docker workflow publishes/scans the fixed images.
Those findings are retained as TPs while that happens. After the main run,
verify the exact published digest on both platforms and GitHub's final alert
states. Previously published image digests remain immutable; deployments need
the newly published fixed image.
