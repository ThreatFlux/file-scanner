# Reviewed CodeQL false positives

CodeQL 2.27.1 reported nine results in the checksum-pinned, unmodified YARA-X
1.21.0 runtime source. Two independent source reviews verified the call paths
below. Changing these public algorithm parameters or legacy forensic identifiers
would change scanner output rather than fix a security vulnerability.

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

The affected paths are relative to `vendor/yara-x-1.21.0`. The ELF path is
`elf::telfhash` → `TlshBuilder::update` → `pearson_hash`. The certificate path is
`parse_certificates` → certificate-chain construction → PE certificate reporting
in `utils/authenticode.rs`; `verify_signer_info` and `CertificateChain::verify`
do not compare the reporting thumbprint.

Primary references: [TLSH source](https://github.com/trendmicro/tlsh/blob/master/src/tlsh_impl.cpp),
[YARA-X ELF documentation](https://virustotal.github.io/yara-x/docs/modules/elf/),
[YARA-X PE documentation](https://virustotal.github.io/yara-x/docs/modules/pe/),
and the [pinned upstream source][upstream].

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

[upstream]: https://github.com/VirusTotal/yara-x/tree/7b2637d4655155fdfaf68177edadb9a39406ece0/lib
[sarif]: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
[action]: https://github.com/github/codeql-action/blob/2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2/analyze/action.yml
[region-default]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
