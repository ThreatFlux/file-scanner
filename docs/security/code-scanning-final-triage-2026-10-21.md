# Final code-scanning triage — 2026-10-21

All 24 open alerts were re-fetched through the paginated GitHub API. The independent reviewer made no GitHub mutations. The parent subsequently applied all 13 recommended code-scanning FP dispositions at the user's request; exact verified dispositions are in [the audit record](alert-dispositions-2026-10-21.json). This report supersedes the earlier conservative 12 TP/package, 10 FP/runtime, 2 uncertain split after collecting both-platform/component-specific evidence. **Final evidence-based split: 13 false positives for the identified runtime components, 11 true affected-package findings needing actual runtime remediation.** Only #266 has a directly observed relevant application interface; other retained package findings have unproven application reachability.

## Both-platform immutable baseline

Published current-main index: `sha256:e0065caf14177e3679f3a90cdacf080133e9bd3ce203c611f6442dfa58fc9cb5`, Git main `a34604292e7060f45d3c6f10b392c326afe2ead1`.

| Platform | Pulled and exported child digest | Findings |
|---|---|---|
| amd64 | `sha256:e0a7920868a9d7509bd8cf23b9b9092bd6693276791213955794bdf002972e78` | No nscd, setuid/setgid files, or installed C++ headers. |
| arm64 | `sha256:e4e4a57c55d542b0dc2f4cb975707e97683e2e8d38c69c985bb6646ab98807d3` | Same absences, independently checked in exported rootfs. |

Both images contain libc6 `2.41-12+deb13u4`, GCC runtime binary packages `14.2.0-19`, zlib1g `1:1.3.dfsg+really1.3.1-1+b1`. Both scanner ELF files need only `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, and import `getaddrinfo`. Neither scanner directly links libstdc++ or zlib. No capability xattr appeared in exported tar metadata, but Docker export absence alone is not a general capability attestation; Dockerfile also introduces no file capabilities. Runtime/container operators must not add privileged binaries or nscd mounts without re-review.

The GCC libstdc++ aligned operator-new function was **disassembled independently for both architectures**, not inferred from package names. amd64 `_ZnwmSt11align_val_t` at `0xb3c20` calls `posix_memalign@plt` at instruction `0xb3c81`; arm64 equivalent at `0xaa1c0` calls it at `0xaa218`. [Upstream GCC fix](https://github.com/gcc-mirror/gcc/commit/200183d4ab5d57575f3dfebc6af3baf649910b9e) explicitly says this POSIX allocation path avoids the vulnerable size-rounding implementation.

## Recommended false-positive dismissals and exact comments

Use GitHub code-scanning `dismissed_reason: "false positive"`; comments below are deliberately bounded to the reviewed published image/components. Parent should record the completed dispositions and API responses. A false-positive disposition does not claim that package versions are patched.

| Alert | Recommended dismissal comment |
|---|---|
| [317](https://github.com/ThreatFlux/file-scanner/security/code-scanning/317) | Reviewed both immutable main amd64 e0a792... and arm64 e4e4a5... images. Disassembly of libstdc++ aligned operator new shows calls to posix_memalign on both. GCC fix 200183d4 explicitly excludes this implementation from CVE-2026-95619's affected rounding paths. Package-version/source matching overstates applicability to these Linux binaries. Scanner also does not link libstdc++. Re-review if target/toolchain changes. |
| [316](https://github.com/ThreatFlux/file-scanner/security/code-scanning/316) | CVE-2026-102010 is in the pbds C++ template header include/ext/pb_ds/detail/binary_heap_/erase_fn_imps.hpp (upstream GCC fix aaa8351f), not libstdc++.so runtime implementation. Both reviewed published runtime images contain no C++ headers, and scanner links no libstdc++. This alert attributes a header-only component issue to the shared-runtime binary package. Any future native C++ consumer must be reviewed/rebuilt against patched headers independently. |
| [290](https://github.com/ThreatFlux/file-scanner/security/code-scanning/290) | gcc-14 source-package fanout: libgomp1 is the OpenMP runtime and does not contain the libstdc++ aligned-new implementation affected by CVE-2026-95619. Independently inspected both published runtime images; component attribution is false. The actual installed libstdc++ POSIX path was also checked separately under alert317. |
| [289](https://github.com/ThreatFlux/file-scanner/security/code-scanning/289) | gcc-14 source-package fanout: libgomp1 is OpenMP runtime, not the pbds C++ template header affected by CVE-2026-102010. Upstream fix aaa8351f modifies include/ext/pb_ds/detail/binary_heap_/erase_fn_imps.hpp. Neither published runtime contains these headers. |
| [281](https://github.com/ThreatFlux/file-scanner/security/code-scanning/281) | gcc-14 source-package fanout: libgcc-s1 provides unwind/compiler support, not the libstdc++ aligned-new allocation code affected by CVE-2026-95619. Confirmed package/component scope in both published platforms. Keep libgcc_s because scanner actually needs it; no removal merely to silence this match. |
| [280](https://github.com/ThreatFlux/file-scanner/security/code-scanning/280) | gcc-14 source-package fanout: libgcc-s1 unwind/support library does not contain the pbds erase_if template affected by CVE-2026-102010; upstream fix aaa8351f changes a C++ template header absent from both published runtimes. |
| [277](https://github.com/ThreatFlux/file-scanner/security/code-scanning/277) | gcc-14-base contains common compiler support/documentation, not libstdc++ aligned-new machine code. CVE-2026-95619 is incorrectly propagated from shared gcc-14 source-package provenance. Both published runtime inventories were inspected; actual libstdc++ implementation applicability reviewed separately under317. |
| [276](https://github.com/ThreatFlux/file-scanner/security/code-scanning/276) | gcc-14-base common support/documentation does not contain the pbds erase_if template header affected by CVE-2026-102010. This is source-package fanout to an unaffected binary package. Both published runtime images contain no C++ headers. |
| [278](https://github.com/ThreatFlux/file-scanner/security/code-scanning/278) | CVE-2026-97399 affects the Power8 optimized strncasecmp implementation. This published image index supports amd64 and arm64 only; both architectures were inspected. Neither contains the PowerPC implementation. Re-review if a PowerPC platform is added. |
| [270](https://github.com/ThreatFlux/file-scanner/security/code-scanning/270) | CVE-2026-95818 requires an AT_SECURE privileged setuid/setgid binary with susceptible ORIGIN rpath. Neither immutable amd64 nor arm64 runtime rootfs contains setuid/setgid files; Dockerfile runs uid 65532 and introduces no capabilities. Required privileged-execution component/configuration is absent in the supported image. Re-review if privileged binaries/capabilities are injected. |
| [269](https://github.com/ThreatFlux/file-scanner/security/code-scanning/269) | CVE-2026-86805 requires an AT_SECURE privileged ORIGIN traversal binary, hardlink ability and race conditions. Neither independently inspected amd64/arm64 runtime has setuid/setgid files; Dockerfile runs uid 65532 and introduces no capabilities. Required privileged target is absent. Re-review if deployment injects privileged binaries/capabilities. |
| [258](https://github.com/ThreatFlux/file-scanner/security/code-scanning/258) | CVE-2026-89092 affects the nscd service. Neither immutable published amd64 nor arm64 runtime rootfs contains nscd; application entrypoint is tini plus scanner. Ordinary getaddrinfo usage is not this nscd service defect. Re-review if an nscd service/socket is introduced. |
| [257](https://github.com/ThreatFlux/file-scanner/security/code-scanning/257) | Version-range false match: installed Debian zlib source is 1:1.3.dfsg+really1.3.1-1, preceding upstream nonblocking-gz introduction81cc0beb (v1.3.1.2). Exact Debian gzwrite.c has neither gz_vacate nor the nonblocking again-state support involved; Debian source patch series is empty. Upstream fix df84af25 addresses that later nonblocking branch. Both published package inventories match1.3.1; scanner links no libz. Debian tracker broad affected status contradicts exact source/component evidence. |

CVE-2026-102010 upstream fix: [GCC aaa8351f](https://github.com/gcc-mirror/gcc/commit/aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6). CVE-2026-85091 source evidence: [exact Debian gzwrite.c](https://sources.debian.org/src/zlib/1%3A1.3.dfsg%2Breally1.3.1-1/gzwrite.c/), [upstream nonblocking introduction](https://github.com/madler/zlib/commit/81cc0bebedd935daeb81b0b6e475d8786b51af3d), [upstream fix](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148), [Debian source packaging archive](https://deb.debian.org/debian/pool/main/z/zlib/zlib_1.3.dfsg+really1.3.1-1.debian.tar.xz). Exact source proof resolves earlier uncertainties316/257; neither is dismissed just because source grep found no application caller.

## Eleven findings requiring actual remediation

Retain as true affected-component/package findings: **22,25,124,187,189,194,204,205,206,207,266**. These are glibc flaws plus zlib CRC-combine flaw124. Direct reachable-interface evidence is strongest for266 (getaddrinfo). Others remain conditional/unproven exploitation, but vulnerable implementations exist, so source grep absence alone does not justify FP disposition.

### Assessed alternative: static MUSL runtime

Build the all-features scanner for explicit `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, then use scratch runtime with the static binary, CA roots, nonroot data directory, SBOM, and a genuinely static init if preserving tini. This removes **actual glibc/GCC shared-library/zlib package components**, rather than deleting package metadata to hide alerts. Static native dependencies still require version provenance and scanning, especially if bundled zlib is linked through libgit2/libz-sys; select patched native zlib or remove unused functionality, not merely its package record.

Verified current official builder: `rust:1.99.1-alpine3.24@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9`. [Official Rust image](https://hub.docker.com/_/rust) supports this tag; [Alpine3.24](https://alpinelinux.org/releases/) is stable supported through2028-06. Rust documents both MUSL targets as Tier2 with host tools; application/native dependency compatibility still requires actual builds. Wasmtime's generic Linux support does not by itself prove this application's static MUSL embedding works.

Acceptance criteria before claiming all TP fixes:

1. Both-platform all-features locked release builds pass. Inspect each executable with readelf/objdump: **no INTERP and no NEEDED**; verify init too. Do not copy glibc tini into scratch.
2. Prove no statically linked vulnerable zlib persists: preserve Cargo/native SBOM, inspect libz-sys configuration and vendored upstream zlib version; ensure CVE-2026-27171 fixed if that native component exists. A scratch scanner cannot infer native component absence merely from lack of dpkg/apk inventory.
3. Run each platform's container as uid 65532: basic file analysis, ZIP/JAR/wheel parsing, real YARA rule compilation/execution (Wasmtime), MCPstdio EOF, HTTP DNS/TLS with CA verification, and signal/child-reaping behavior. Preserve user-facing CLI compatibility.
4. Scan exact immutable outputs with current Trivy DB at **all severities** and produce native/library-aware SBOM. Preserve JSON/SARIF, DB timestamps and architecture/digest. No blanket ignore files or severity-only filtering to make the dashboard green.
5. Merge/publish and run same-category main analysis to mark TP alerts fixed. Do **not** dismiss affected TPs as false positives simply because a future image is planned.

### Supported newer stable GNU distro alternative

Ubuntu26.10 is a released stable option ([release index](https://releases.ubuntu.com/)) and its official CVE pages mark the **ten glibc CVEs** retained above not affected, while Ubuntu26.04 LTS still has unresolved/evaluation cases for8674/18374. Example [Ubuntu8674](https://ubuntu.com/security/CVE-2026-8674). A minimal Ubuntu26.10 runtime with exactly needed shared libraries could avoid a MUSL migration, but needs version/digest scan proof, zlib124 validation, security-update lifecycle management, and runtime ABI tests. The latest Debian13/distroless refresh alone is insufficient: Debian tracker still marks the baseline trixie components vulnerable and no stable fixes are listed. Do not mix Debian sid glibc into trixie.

No new runtime build or test was performed by this reviewer; parent owns implementation. The implemented route is instead the smaller Wolfi GNU runtime migration described in [the remediation record](security-alert-remediation-2026-10-21.md), with the native zlib security backport. Static MUSL was assessed but is not the shipped change. If MUSL platform builds fail, choose a validated supported newer distro rather than trading away existing features or hiding scanner results.

## Exact bounded GitHub API payloads

Each body is for PATCH `/repos/ThreatFlux/file-scanner/code-scanning/alerts/{number}`. All comments are at most280 characters.

```json
[
  {
    "number": 257,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/version: Exact Debian zlib 1.3.1 gzwrite.c lacks gz_vacate/nonblocking again-state; Debian patch series empty. Vulnerable feature introduced upstream 81cc0beb in 1.3.1.2; fix df84af25 concerns that later branch. Both main inventories confirm 1.3.1."
    }
  },
  {
    "number": 258,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: CVE-2026-89092 affects nscd service. Neither immutable main amd64/arm64 rootfs contains nscd; entrypoint is tini plus scanner. Ordinary getaddrinfo is not this defect. Re-review if an nscd service/socket is introduced."
    }
  },
  {
    "number": 269,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/runtime: CVE-2026-86805 requires a privileged AT_SECURE ORIGIN traversal binary. Both immutable main rootfs inventories have no setuid/setgid files; Dockerfile adds no capabilities and runs uid 65532. Re-review if privileged binaries/capabilities are added."
    }
  },
  {
    "number": 270,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/runtime: CVE-2026-95818 requires a privileged AT_SECURE target with susceptible ORIGIN rpath. Neither immutable main amd64/arm64 rootfs has setuid/setgid files; Dockerfile runs uid 65532 with no added capabilities. Re-review privileged deployment changes."
    }
  },
  {
    "number": 276,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: gcc-14-base common support/docs contain no pbds erase_if template header affected by CVE-2026-102010. GCC fix aaa8351f modifies a C++ header absent from both immutable main runtime images."
    }
  },
  {
    "number": 277,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: gcc-14-base common support/docs contain no libstdc++ aligned-new code. CVE-2026-95619 source-package attribution is overbroad. Both main platforms inspected; actual libstdc++ POSIX path reviewed separately in 317."
    }
  },
  {
    "number": 278,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/architecture: CVE-2026-97399 affects Power8 strncasecmp only. Published main index e0065c supports amd64/arm64, independently inspected, with no PowerPC implementation. Re-review if a PowerPC target is added."
    }
  },
  {
    "number": 280,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: libgcc-s1 unwind/support library does not contain the pbds erase_if template affected by CVE-2026-102010. GCC fix aaa8351f changes a C++ header absent from both immutable main runtimes."
    }
  },
  {
    "number": 281,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: libgcc-s1 unwind/compiler support is not libstdc++ aligned-new code affected by CVE-2026-95619. gcc-14 source-package matching incorrectly fans out to this binary package. Both published main platforms inspected."
    }
  },
  {
    "number": 289,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: libgomp1 OpenMP runtime contains no pbds erase_if C++ template header affected by CVE-2026-102010. GCC fix aaa8351f modifies that header. Both immutable main runtime images contain no C++ headers."
    }
  },
  {
    "number": 290,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: libgomp1 is OpenMP runtime, not libstdc++ aligned-new code. CVE-2026-95619 is propagated from gcc-14 source provenance to an unaffected binary package. Both main image inventories checked; actual libstdc++ applicability reviewed in 317."
    }
  },
  {
    "number": 316,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP/component: GCC fix aaa8351f affects the pbds erase_if C++ template header, not libstdc++.so runtime code. Both immutable main images e0a792/e4e4a5 contain no C++ headers; scanner links no libstdc++. Future compiled C++ consumers need separate review."
    }
  },
  {
    "number": 317,
    "body": {
      "state": "dismissed",
      "dismissed_reason": "false positive",
      "dismissed_comment": "FP: Both main amd64/arm64 libstdc++ aligned-new disassemblies call posix_memalign, which GCC fix 200183d4 explicitly excludes from the vulnerable rounding paths. Inspected immutable images e0a792/e4e4a5; scanner also links no libstdc++."
    }
  }
]
```
