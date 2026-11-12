# Reviewed stable YARA-X runtime/crypto patch

Repository-built binaries and containers select the official YARA-X1.23.0
source with Wasmtime50.0.1 and stable RSA0.10.0. The upstream manifest still
requires Wasmtime48.0.8 and a prerelease RSA requirement. This explicit patch
changes the actual parent requirements instead of forcing lockfile transitives.

- Official archive SHA256: `e8a5ff1e1bb43734cc68f3ddc94646c9740c8c559d38fae559f0c79076f801db`.
- Verified against [the official sparse index](https://index.crates.io/ya/ra/yara-x) on2026-11-12.
- Upstream commit: [`afe4585b12f56c698794dc80b3d28ddb87b56c0a`](https://github.com/VirusTotal/yara-x/tree/afe4585b12f56c698794dc80b3d28ddb87b56c0a/lib).
- BSD-3-Clause license and upstream source/build assets are preserved.
- [Exact local diff](yara-x-1.23.0.patch): stable RSA0.10 with its newly required
  `pkcs1v15` feature, Wasmtime50.0.1, current `rsa::PublicKey` aliases, and the
  independent OpenSSL signature regression retained from the previous patch.
  Original workspace/lock/VCS metadata and benchmark declarations are omitted.

YARA-X1.23's global-linker implementation compiles against Wasmtime50 without a
runtime source bridge. RSA0.10 shares the current digest/PKCS8 generation, so
the old RSA0.9-specific digest aliases are no longer needed. Only public-key
signature verification is present. The obsolete RUSTSEC-2023-0071 waiver is
removed; the source guard now requires stable0.10, one YARA caller and no waiver.

The historical1.22 patch remains at [yara-x-1.22.0.patch](yara-x-1.22.0.patch),
and its complete source is preserved in Git history. The fixed public-key,
prefixed/unprefixed signatures and negative controls move unchanged to1.23.
The isolated `ci/yara-crypto-compat` harness imports the actual reviewed ASN.1
and crypto modules and runs these independent vectors on hosted runners.

The sealed CodeQL policy retains exact rule/path/full-region/raw-message tuples,
source/caller inventories and fail-closed behavior. ELF/TLSH/ASN.1/Authenticode
call-path files are byte-identical to the prior review. The PE diff repairs
overflow and missing-metadata handling while keeping forensic hashing semantics.
The new path fixture is explicitly simulated; all historical native SARIF
evidence remains unchanged. Fresh native output is required before merge.

This root override affects repository binaries/containers, and does not propagate
to downstream crates.io consumers. Their parent graph remains upstream's graph.
Remove the vendor only after a published stable YARA release supports the desired
stable runtime/crypto graph and hosted native/signature/CodeQL parity passes.

# Temporary binary-analysis ZIP security patch

Superseded for repository builds on 2026-11-12 by published
`threatflux-binary-analysis` 0.3.2 (ZIP 9.5.1). A full source comparison verified
that its Java parser retains the reviewed fallible ZIP-name bridge. Its only
additional source changes are formatting, the CP437 archive-name regression,
the wasmparser range API migration with explicit bounds validation and tests,
and the equivalent `as_chunks` pattern iteration. The active root patch is
removed; the historical source and exact diff below remain for provenance.
Hosted archive, native and security checks validate the registry replacement.

The latest published `threatflux-binary-analysis` 0.3.1 requires ZIP 8.6.0,
which is reported by RustSec advisories RUSTSEC-2026-0367, RUSTSEC-2026-0368 and
RUSTSEC-2026-0369. The root patch uses the exact published crate with ZIP 9.0.5
and the small necessary API migration. No additional advisory exceptions are
introduced. Its only ZIP caller is the Java/JAR metadata parser; it reads entry
names and sizes and never extracts files or writes archive paths to disk. This
patch removes the affected package version from the graph even though the
extraction-specific paths are not called here.

## Binary-analysis provenance and changes

- Artifact: [crates.io threatflux-binary-analysis 0.3.1](https://static.crates.io/crates/threatflux-binary-analysis/threatflux-binary-analysis-0.3.1.crate).
- SHA-256: `ac8769597acfe127518ffacbc8819c4f3ff8094241dd7ae7211502e008d79eb0`.
- Verified against the [official crates.io index](https://index.crates.io/th/re/threatflux-binary-analysis) on 2026-10-21.
- Upstream VCS commit: [`64856368e7007d1292ad7b2603b8cd5ccd3dd7df`](https://github.com/ThreatFlux/threatflux-binary-analysis/tree/64856368e7007d1292ad7b2603b8cd5ccd3dd7df).
- MIT [LICENSE](threatflux-binary-analysis-0.3.1/LICENSE), source, tests, examples and shipped documentation are retained from the archive.
- Exact changes: [manifest and Java parser diff](threatflux-binary-analysis-0.3.1.patch).

The normalized Cargo manifest bumps normal and development ZIP dependencies
from 8.6.0 to 9.0.5. Java parsing propagates invalid entry-name errors; Java
format detection treats invalid names as nonmatching. ZIP 9 returns a fallible
`Cow<str>` name, so the parser borrows the decoded name when copying it into the
bounded output. No extraction or filesystem behavior is added. The package's
Cargo.lock, original manifest and VCS metadata are omitted from the vendor copy.

All six existing Java parser unit regressions passed against this ZIP 9.0.5
patch in an isolated copy: ordinary JAR identification, generic ZIP rejection,
truncated or invalid Java headers, forged archive entry counts and two EOCD
comment-signature cases. The root compilation and archive integration tests
provide additional coverage with the full application feature set.

As with YARA-X, the root patch affects repository-built binaries/containers and
is not inherited by crates.io library consumers. Remove this override once a
published stable binary-analysis release requires a fixed stable ZIP version;
refresh the lockfile, audit/deny and rerun Java/archive regressions. The public
crate can resolve the unpatched upstream ZIP dependency until that happens.

# Stable libz-sys / zlib security backport

The root `libz-sys` patch preserves the stable wrapper 1.1.31 and its
bundled stable zlib 1.3.2, with the exact upstream fix for CVE-2026-85091.
`libz-sys` 1.1.31 also removes the build-script probe logging that caused
RUSTSEC-2026-0418.
`LIBZ_SYS_STATIC=1` in the production build selects this bundled implementation;
using an unaffected runtime base alone would not repair vulnerable statically
linked C code. This patch changes the actual source compiled into the binary.

## libz-sys provenance

- Artifact: [official libz-sys 1.1.31 crate](https://static.crates.io/crates/libz-sys/libz-sys-1.1.31.crate).
- Archive SHA-256: `ff20308ecabd635a2dc1dd5834a86c462cca20efba1d5d3ddab1f8aea3455cb2`.
- Checksum verified against the 1.1.31 entry in the [official crates.io registry](https://crates.io/api/v1/crates/libz-sys/1.1.31) on 2026-10-31.
- Crate VCS commit: [`595fbb7995b2c5e15371963103d33192fd066857`](https://github.com/rust-lang/libz-sys/tree/595fbb7995b2c5e15371963103d33192fd066857), from its packaged VCS metadata.
- The original MIT/Apache licenses and embedded zlib license notice in `src/zlib/zlib.h` are preserved.
- Original source, build script, normalized manifest and included zlib/zlib-ng trees are preserved. Package Cargo.lock, original Cargo.toml and VCS metadata are omitted.
- Exact upstream-source diff: [libz-sys-1.1.31.patch](libz-sys-1.1.31.patch).

The patch is a direct backport of Mark Adler's official zlib commit
[`df84af25dc1942490e1d1c899a07619152a46148`](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148),
"Fix buffer overflow bug in non-blocking gzwrite", dated 2026-09-16. The complete
commit identity and patch were verified using GitHub's authenticated commit API
and the official commit patch. Upstream explicitly identifies CVE-2026-85091.

When a direct large-buffer gzip write stalls, `gz_write` must clear remaining
input and reset its input pointer to its owned buffer before returning. Without
that reset, a subsequent small write can derive an out-of-bounds destination
from the previous caller's input pointer. The backport is exactly upstream's
four added lines and one removed line in `src/zlib/gzwrite.c`; it neither changes
version identifiers nor assumes the affected code is unreachable. No advisory
ignore or prerelease dependency is introduced.

## Native regression

Run from the repository root with a POSIX C compiler supporting AddressSanitizer:

```sh
vendor/libz-sys-1.1.31/tests/check-gzwrite-backport.sh
```

The test compiles the actual vendored stock zlib C sources with AddressSanitizer.
It fills a nonblocking pipe, stalls a large direct `gzwrite`, asserts that the
stream points to its owned buffer with no pending input, and checks that the
next smaller write can safely buffer its input. The patched source passes.
As a negative control, the same test compiled against the pristine official
1.1.30 crate fails the input-state assertion. The official 1.1.31 crate retains
the same unpatched `gzwrite.c`, so this backport remains necessary. The negative
control proves the regression detects the absent security fix independently of
scanner/package version heuristics.
Only source and the test runner are retained; test executables are temporary.

As with the other root patches, downstream crates.io consumers must supply their
own top-level patch to receive this backport. Remove it only after a published
stable libz-sys includes the upstream fix (or a newer fixed stable zlib), then
refresh the lockfile, rerun the native regression and final container scans, and
inspect actual bundled native sources as well as Cargo package versions.
