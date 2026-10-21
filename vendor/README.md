# Temporary stable YARA-X dependency patch

The root Cargo patch uses the published stable YARA-X 1.22.0 source with stable
Wasmtime 49.0.4 and RSA 0.9.10. Upstream 1.22.0 requires Wasmtime 48.0.6 and the
prerelease RSA 0.10.0-rc.19. This patch keeps the repository on stable dependencies
while refreshing YARA-X and the native runtime. The existing public-key-only
RSA advisory exception remains guarded by `scripts/check-rsa-exception.py`;
this update adds no advisory exemptions.

## Provenance

- Artifact: [crates.io YARA-X 1.22.0](https://static.crates.io/crates/yara-x/yara-x-1.22.0.crate).
- Artifact SHA-256: `219e5694590ea59d31c880b4bb88f78cf82f69b58c590d710577ee277aacfb2d`.
- Verified against the 1.22.0 entry in the official [crates.io sparse index](https://index.crates.io/ya/ra/yara-x) on 2026-10-21.
- Upstream commit from the crate's `.cargo_vcs_info.json`: [`e27597f2c05e13fe1c2bb459781aef8899afc485`](https://github.com/VirusTotal/yara-x/tree/e27597f2c05e13fe1c2bb459781aef8899afc485/lib).
- License: BSD-3-Clause; [LICENSE](yara-x-1.22.0/LICENSE) is verified byte-for-byte against that upstream commit.
- Local manifest and source changes: [exact diff](yara-x-1.22.0.patch).

Upstream source, generated module assets, build script and README are preserved
except for the documented crypto API bridge. Upstream Cargo.lock, original
workspace Cargo.toml, standalone benchmark targets/files and package VCS metadata
are omitted because this crate is a dependency of the root workspace. Existing
runtime features remain `cranelift` and `runtime`, with default features disabled;
this patch enables no component-model or WASI features. Git whitespace attributes
and formatting hooks exempt the upstream subtree and exact diff context, while
application compilation, lint and security gates still apply.

## Stable RSA compatibility

YARA-X 1.22.0 uses current stable RustCrypto digest 0.11, DSA 0.7 and ECDSA 0.17.
Stable RSA 0.9.10 still consumes digest 0.10 and PKCS8 0.10, whereas upstream's
prerelease RSA shares the newer crypto traits. The local bridge retains the
current stable crypto dependencies and uses four explicit compatibility aliases
for RSA's own PKCS#1 v1.5 padding constructors: md2 0.10.2, md-5 0.10.6,
sha1 0.10.7 and sha2 0.10.9. These older stable series coexist with the latest
stable digest implementations. Actual message hashing uses the current stable
algorithms. An OID selects the corresponding RSA padding constructor; the
upstream unprefixed-signature fallback is preserved. ECDSA imports its own newer
public-key decode trait and error type, separately from RSA's older PKCS8 type.
No private-key operations are introduced.

The added `stable_rsa_tests::stable_rsa_verifies_openssl_sha256_signatures`
regression checks independent OpenSSL-generated SHA256 signatures with both
standard DigestInfo padding and the upstream unprefixed fallback, rejects a
modified message and rejects a corrupted signature. Only the public key and
signatures are stored under `src/modules/utils/testdata/`; no private key is
retained. The vectors were generated with:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
printf 'YARA-X stable RSA compatibility regression\n' > message
openssl pkey -in key.pem -pubout -outform DER -out stable-rsa-public.der
openssl dgst -sha256 -sign key.pem -out stable-rsa-prefixed.sig message
openssl dgst -sha256 -binary -out digest message
openssl pkeyutl -sign -inkey key.pem -in digest -out stable-rsa-unprefixed.sig
```

The targeted regression was compiled and passed in an isolated Cargo harness
using the actual vendored crypto and ASN.1 modules. Root CI additionally exercises
real YARA rule compilation and scanning. The exception guard verifies the exact
reviewed crypto source, the sole RSA caller and version, and absence of RSA in
the standalone package-security crate.

## Distribution scope and removal

This override applies to native binaries and Docker images built from this
repository. Cargo does not propagate root `[patch.crates-io]` overrides into a
published library, and the package `include` allowlist excludes the vendor tree.
The `threatflux-file-scanner` package on crates.io therefore resolves upstream
YARA-X 1.22.0 with its original Wasmtime requirement and prerelease RSA dependency.
A library consumer requiring this exact stable graph must add a complete
root-level patch or use this repository's binaries, container or source checkout.
This scope limitation must remain visible in release documentation.

Remove the root patch and vendor tree when a published stable YARA-X release
uses stable RSA and an acceptable stable Wasmtime runtime. Regenerate Cargo.lock,
run vulnerability audit/deny (including a no-ignore report for the retained RSA
exception), verify no prerelease packages remain, rerun the RSA regression and
YARA compile/scan tests, and rereview the CodeQL source-hash guard before removal.

# Temporary binary-analysis ZIP security patch

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
