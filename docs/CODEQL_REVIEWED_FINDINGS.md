# Reviewed CodeQL false positives

CodeQL 2.27.1 originally reported nine results in YARA-X 1.21.0. The
2026-10-21 dependency rollup explicitly re-reviewed the same nine source contexts
and their callers in checksum-pinned YARA-X 1.22.0, including its documented
stable RSA/Wasmtime compatibility patch. The current policy covers only the
1.22.0 paths. Changing these public algorithm parameters or legacy forensic
identifiers would change scanner output rather than fix a security vulnerability.

The eight `rust/hard-coded-cryptographic-value` results concern the TLSH Pearson
permutation in `src/modules/elf/tlsh/helper.rs` and seven fixed parameters in
`src/modules/elf/tlsh/mod.rs`. These are public parameters of a deterministic
similarity hash, used only to compute ELF `telfhash` from symbol names. They match
the official TLSH algorithm; they are not cryptographic secrets or password salts.

The `rust/weak-sensitive-data-hashing` result concerns the certificate thumbprint
in `src/modules/utils/asn1.rs`. SHA-1 identifies a public certificate in PE forensic
metadata. The thumbprint is copied into output; it does not decide certificate
validity, signature verification, or trust. Authenticode digest, signature, and
embedded-chain verification use separate paths. Embedded-chain verification is
not a claim of operating-system root trust.

The affected paths are relative to `vendor/yara-x-1.22.0`. The ELF path is
`elf::telfhash` → `TlshBuilder::update` → `pearson_hash`. The certificate path is
`parse_certificates` → certificate-chain construction → PE certificate reporting
in `utils/authenticode.rs`; `verify_signer_info` and `CertificateChain::verify`
do not compare the reporting thumbprint.

Primary references: [TLSH source](https://github.com/trendmicro/tlsh/blob/master/src/tlsh_impl.cpp),
[YARA-X ELF documentation](https://virustotal.github.io/yara-x/docs/modules/elf/),
[YARA-X PE documentation](https://virustotal.github.io/yara-x/docs/modules/pe/),
and the [pinned upstream source][upstream].

## YARA-X 1.22.0 source re-review

The TLSH helper permutation and builder source are byte-for-byte unchanged from
1.21.0. Each of the seven selector regions (305, 330, 338, 346, 354, 362, 370) and
the helper table (9–26) retains its original value and full region. ELF `telfhash`
still hashes sorted, normalized public symbol names through `TlshBuilder` and
`pearson_hash`; the ELF module's separate import-MD5 change only switches its
hex formatting API. No secret or authentication caller was introduced.

ASN.1 certificate parsing is byte-for-byte unchanged, including line 244's SHA-1
thumbprint. The thumbprint is copied into PE certificate/signature reporting.
The Authenticode change serializes the signed-attribute DER SET into a byte buffer
before hashing, replacing the previous streaming writer. Signer selection still
uses certificate serial numbers, chain verification still verifies raw certificate
signatures with parent public keys, and neither path consumes the thumbprint.
The stable RSA patch selects the same six digest OIDs through RSA 0.9-compatible
padding constructors, verifies the provided digest, and preserves the existing
unprefixed-signature fallback; DSA/ECDSA remain prehash verification. This review
does not endorse legacy signature algorithms or claim operating-system-root trust.
No suppression covers those verification functions or newly reported findings.

The complete token inventory was rechecked: changes outside these call paths
are protobuf numeric-field representation updates, PE offset conversion, conditional
test-module documentation, and ZIP 9 fallible-name adaptations in the two Java
analyzers. The generated thumbprint accessors retain their reporting/serialization
role. The added binary-analysis vendor contributes two inventoried files: its PE
parser marks `signed` from certificate-table presence and its type documents that
reporting field; neither consumes a YARA-X certificate or thumbprint. Every changed inventoried file is pinned, as are the updated vendor manifest,
Wasmtime 49.0.5 resolution and crypto verification implementation. The nine
justifications therefore remain valid under the narrower, exact 1.22.0 tuples.

The 2026-10-31 Wasmtime security update changes the vendored manifest's minimum
from 49.0.4 to 49.0.5 and the reviewed dependency version. The inventoried
YARA-X algorithm, certificate, and crypto caller sources are unchanged; their
source hashes and the nine exact reviewed result tuples remain the same.

The historical API fixture `scripts/codeql-reviewed-findings-fixture.sarif` and
compressed CLI evidence `scripts/codeql-reviewed-findings-raw-25c41d9.sarif.gz`
remain byte-for-byte intact. They describe 1.21.0 and are **not** fresh 1.22.0
CodeQL output. Tests prove their historical paths are retained without omissions
under the new policy. The explicitly named
`scripts/codeql-reviewed-findings-fixture-1.22-simulated.sarif` changes only vendor
paths for regression coverage; another test migrates raw CLI paths in memory to
exercise omitted `endLine` normalization. Neither simulation claims a new native
analysis. Fresh CodeQL may produce different tuples; those remain uploaded.

## Review guard and retained evidence

The checked-in `.github/codeql-reviewed-findings.json` records exact rule IDs,
paths, complete source regions, messages, and explanations for these nine results.
For matching only, a missing `endLine` defaults to the positive integer `startLine`,
as required by [SARIF 2.1.0, section 3.30.7][region-default]. Raw CodeQL omits this
redundant value for single-line findings; GitHub's API adds it. Explicit values
and every other region component remain unchanged. This normalization preserves
the same nine source ranges and leaves the raw evidence untouched.
`scripts/codeql-reviewed-findings.py` verifies the pinned YARA-X version and source
hashes, including related call paths and an inventory of relevant symbol uses.
It fails if the reviewed source, version, or caller inventory changes. Regression
tests exercise changed source, new callers, duplicate results, and unmatched
findings. Run `make codeql-review-check` to check these conditions locally.

CodeQL continues to run every configured query over application and vendor source.
There are no rule-wide or directory-wide exclusions. The workflow retains the
raw analysis, an annotated copy with rule-specific explanations, and a review
receipt as an artifact and prints the review count in the job summary. Only
results matching the verified nine tuples are omitted from the uploaded copy;
every other result is preserved. No repository alert is dismissed through the API.

This post-processing is necessary because Rust inline suppression is
[not implemented upstream](https://github.com/github/codeql/issues/21637), and
`suppressions` is absent from GitHub's [supported SARIF fields][sarif].
The [official analysis action][action]
supports generating SARIF for post-processing before upload. Analysis failures
remain failures. Remove this review mechanism when the upstream Rust queries
recognize these non-security uses; re-review it when the vendor is updated.

[upstream]: https://github.com/VirusTotal/yara-x/tree/e27597f2c05e13fe1c2bb459781aef8899afc485/lib
[sarif]: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
[action]: https://github.com/github/codeql-action/blob/6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee/analyze/action.yml
[region-default]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
