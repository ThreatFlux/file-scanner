# Reviewed stable YARA-X runtime/crypto patch

Repository-built binaries and containers select the official YARA-X 1.23.0
source with Wasmtime 50.0.1 and stable RSA 0.10.0. The upstream manifest still
requires Wasmtime 48.0.8 and a prerelease RSA requirement. This explicit patch
changes the actual parent requirements instead of forcing lockfile transitives.

- Official archive SHA256: `e8a5ff1e1bb43734cc68f3ddc94646c9740c8c559d38fae559f0c79076f801db`.
- Verified against [the official sparse index](https://index.crates.io/ya/ra/yara-x) on 2026-11-12.
- Upstream commit: [`afe4585b12f56c698794dc80b3d28ddb87b56c0a`](https://github.com/VirusTotal/yara-x/tree/afe4585b12f56c698794dc80b3d28ddb87b56c0a/lib).
- The BSD-3-Clause license is retained from that exact upstream commit (the crate archive omits it); SHA256 `fdf05444c9178e662fa28810d94a1fa6ec32d7be798241c98094213317265880`. Upstream source/build assets are preserved.
- [Exact local diff](yara-x-1.23.0.patch): stable RSA 0.10 with its newly required
  `pkcs1v15` feature, Wasmtime 50.0.1, current `rsa::PublicKey` aliases, and the
  independent OpenSSL signature regression retained from the previous patch.
  Original workspace/lock/VCS metadata and benchmark declarations are omitted.

YARA-X 1.23's global-linker implementation compiles against Wasmtime 50 without a
runtime source bridge. RSA 0.10 shares the current digest/PKCS8 generation, so
the old RSA 0.9-specific digest aliases are no longer needed. Only public-key
signature verification is present. The obsolete RUSTSEC-2023-0071 waiver is
removed; the source guard now requires stable 0.10, one YARA caller and no waiver.

The historical 1.22 patch remains at [yara-x-1.22.0.patch](yara-x-1.22.0.patch),
and its complete source is preserved in Git history. The fixed public-key,
prefixed/unprefixed signatures and negative controls move unchanged to 1.23.
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

The then-current published `threatflux-binary-analysis` 0.3.1 required ZIP 8.6.0,
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

# Reviewed stable libz-sys and zlib source

The active native override now contains the unmodified official `libz-sys`
1.1.33 source and bundled stable zlib 1.4, released upstream 2026-11-05. Its
`gz_write` error path contains the complete input reset from the previous
CVE-2026-85091 backport, plus upstream's later fixes. The exact native build
script is unchanged from the reviewed 1.1.31 wrapper; the CRC diff adds an
explicit integer cast. No local C edit is needed on this release.

- [Official 1.1.33 crate](https://static.crates.io/crates/libz-sys/libz-sys-1.1.33.crate),
  SHA256 `fee3f59f4321dab0c78d828942e7aa09d0bd8ad6e78a501977e6bf3d02938045`,
  verified against the official sparse index on 2026-11-12.
- [Upstream zlib 1.4 release](https://github.com/madler/zlib/releases/tag/v1.4).
- Original wrapper/native licenses and bundled source are preserved; Cargo
  workspace/lock/VCS metadata are omitted as in the previous override.
- The prior [exact security backport](libz-sys-1.1.31.patch) remains for
  historical provenance; complete prior sources remain in Git history.

The unchanged AddressSanitizer nonblocking-gzwrite regression moves with the
new source, and hosted checks compile the actual bundled C files. Its historical
negative control against pristine 1.1.30 detected the absent security fix. The
source guard now pins the actual 1.1.33 manifest/build/header/CRC/gzip hashes,
requires the local native source and retains `LIBZ_SYS_STATIC=1` before the
production build. Fresh hosted native and archive/container parity is required.

This source override continues to affect repository binaries/containers only.
Downstream library users must independently select an appropriate native source
and build configuration; root Cargo patches do not propagate to consumers.
