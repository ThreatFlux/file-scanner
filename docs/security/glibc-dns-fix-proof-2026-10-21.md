# Exact Wolfi glibc source: DNS advisory fix verification

Reviewed 2026-10-21. Runtime package glibc-2.44 2.44-r8 uses Wolfi's recipe source revision `34106fee698c83eb0af71d4d0381e66b399be746` on release/2.44/master. The exact upstream GNU tools mirror archive was downloaded by the code-scanning reviewer and extracted at `/tmp/file-scanner-glibc34106`. Source `version.h` reports stable2.44. Archive endpoint: https://gitlab.com/gnutools/glibc/-/archive/34106fee698c83eb0af71d4d0381e66b399be746/glibc-34106fee698c83eb0af71d4d0381e66b399be746.tar.gz .

GitHub's bminor mirror does not expose that release branch or commit, but it exposes the actual original fix commits, including complete commit SHA and patch. Each official patch was fetched, inspected, and successfully **reverse-applied in dry-run mode** against the exact Wolfi source with no fuzz or offset. This verifies every fixed hunk is present; no source files were changed. It is stronger than inferring safety from an absent scanner finding or a greater version number.

| Alert | CVE | Official fix | Verified source state |
|---|---|---|---|
| #266 | CVE-2026-8674 | https://github.com/bminor/glibc/commit/506ea57086bfb9ce3daff1c14246a1cb532aba0a | `resolv/resolv_conf.c` accepts empty legacy list when first domain exceeds256-byte storage, and tests remaining `defdname` space instead of incorrectly comparing pointer-array size. Upstream search/domain regression additions also match. |
| #25 | CVE-2026-6238 | https://github.com/bminor/glibc/commit/a7b60d23bbb56eaef59f4962e4140062e552600a | `resolv/ns_print.c` validates LOC exact16-byte RDATA length and A6 minimum/prefix/address-suffix lengths. CERT/TKEY/TSIG handling had already been replaced by generic formatting in the preceding fix. |
| #22 | CVE-2026-5435 | https://github.com/bminor/glibc/commit/ca44a6609c29a683b03575fa035c6d17aa591e72 | `resolv/ns_print.c` removes vulnerable TSIG-specific formatting (and CERT/TKEY/OPT branches), using bounded generic formatting instead. |

Commands, each returning status0:

```sh
patch --dry-run -R -p1 -d /tmp/file-scanner-glibc34106 < /tmp/file-scanner-glibc-8674.patch
patch --dry-run -R -p1 -d /tmp/file-scanner-glibc34106 < /tmp/file-scanner-glibc-5435.patch
patch --dry-run -R -p1 -d /tmp/file-scanner-glibc34106 < /tmp/file-scanner-glibc-6238.patch
```

The local patch files are verbatim upstream GitHub commit `.patch` responses. Full API commit evidence for6238 is also saved at `/tmp/file-scanner-glibc-cve6238-commit.json`.

## Reachability correction

CVE-2026-8674 affects normal resolver initialization, including long search domains in resolv.conf or LOCALDOMAIN. Its source patch inclusion is therefore material for ordinary DNS usage.

The glibc CNA's CVE-2026-6238 record explicitly says the affected deprecated DNS-printing/debugging functions are **not in the path executed by the DNS resolver**. CVE-2026-5435 affects the same `ns_sprintrrf` family. Ordinary outbound DNS calls alone do not demonstrate these two findings are executable in file-scanner. That does not weaken remediation: the precise native source fixes are present regardless. Primary record: https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/6xxx/CVE-2026-6238.json .

No new vulnerability dismissals, repository edits, custom advisory exemptions or source modifications were made during this independent verification. The parent reviewer independently found a Chainguard OSV package fixed-version mapping; this note records separate upstream source evidence.
