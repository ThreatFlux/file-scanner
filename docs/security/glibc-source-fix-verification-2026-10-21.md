# Exact Wolfi glibc source fix verification — 2026-10-21

**All ten glibc findings have fixed implementations in the exact source revision pinned by the Wolfi 2.44-r8 recipe. No missing-fix blocker was found.** This conclusion is based on source inspection and exact upstream-patch reverse checks, independently of Trivy's zero-findings result. This review did not build glibc or execute its full test suite.

## Exact source provenance

The official [Wolfi glibc-2.44 recipe](https://github.com/wolfi-dev/os/blob/b71c93b89f2aa676401abde131f262747739e740/glibc-2.44.yaml) sets package version **2.44**, epoch **8**, release branch `release/2.44/master`, expected source commit **34106fee698c83eb0af71d4d0381e66b399be746**. [Epoch-8 update](https://github.com/wolfi-dev/os/commit/abb5d22d20a78b27e095b0bd9aa16d6c9d2eecfd) changed the previous source pin to this revision. The configured source is the GNU-recommended GitLab mirror.

Downloaded the [exact commit archive](https://gitlab.com/gnutools/glibc/-/archive/34106fee698c83eb0af71d4d0381e66b399be746/glibc-34106fee698c83eb0af71d4d0381e66b399be746.tar.gz), not a moving branch. SHA-256: **7ed4d984e60a8d40cbe4c74b16f9bfba4564f07839f5081dda422252f65b30c0**. Its root is named for that exact revision; `version.h` declares stable 2.44. Extracted read-only review tree: `/tmp/file-scanner-glibc34106`.

GitHub bminor mirror lacks this exact revision/branch (404/422), and GitLab raw endpoints failed; the exact GitLab archive endpoint succeeded. The release branch has an `advisories` text pointer to master, not an advisory directory. Therefore missing advisory files in this archive were not mistaken for missing fixes.

## Every retained glibc finding

Line numbers below refer to the downloaded exact source tree, with hashes below.

| Alert / CVE | Fixed-source evidence at revision34106 | Cross-check |
|---|---|---|
| 187 / CVE-2026-6791 | `posix/wordexp.c:337–375`: tilde username uses `scratch_buffer_set_array_size` and `scratch_buffer_grow_preserve`; untrusted username is copied into growable managed storage, replacing input-sized `strndupa`. | Official [GLIBC-SA-2026-0013](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0013;hb=HEAD) describes unbounded stack allocation and affected versions through2.43. Exact tree includes and registers `posix/tst-wordexp-tilde.c` (BZ34091), including large-username/small-stack coverage. |
| 189 / CVE-2026-6368 | `posix/wordexp.c:2227–2280,2475–2485`: WRDE_APPEND duplicates the caller's pointer array before reallocating; error rollback frees appended entries/working copy and restores the saved original array, preventing stale caller pointers. | Official [GLIBC-SA-2026-0014](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0014;hb=HEAD) identifies stale rollback pointers through2.43. Exact tree includes and registers `posix/tst-wordexp-append.c`, forcing realloc relocation (BZ34090). |
| 206 / CVE-2026-18374 | `libio/fileops.c:358–370`: explicit empty stripped charset guard `ccs[2] == '\0'` rejects with EINVAL, closes the opened file and frees allocation before conversion loading. | Source comment explicitly names **CVE-2026-18374/BZ34574**. Exact tree includes and registers `libio/tst-fopen-ccs-empty.c`; it verifies empty/stripped-empty ccs mode fails with EINVAL. |
| 204 / CVE-2026-19499 | `stdlib/strfmon_l.c:552–563`: remembers actual `written_width`, pads with bounded printf-buffer machinery, stops on failed bounds check, and moves exactly `written_width` bytes for right justification. The previous overflowing move pattern is absent. | Exact tree includes and registers `stdlib/tst-strfmon-bug34510.c`; its first line explicitly names **CVE-2026-19499**, with fault-boundary output tests. |
| 194 / CVE-2026-19542 | `misc/tsearch.c:408–417`: tdelete uses conservatively bounded `2 * UINTPTR_WIDTH` parent stack rather than fragile growing alloca arrays; pushes are guarded at lines429,468,533,618. | Official fix [e2789c46](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2789c46e3bfdcd67a82bea9946b315c179e83d3) patch reverse-applies exactly to `misc/tsearch.c` in the pinned tree, with no fuzz or offset. |
| 205 / CVE-2026-77117 | `iconvdata/shift_jisx0213.c:229–234`: on pending-character retry it explicitly clears `*statep = 0` before output, ensuring that the buffered second code point is emitted once and conversion progresses. | Official [GLIBC-SA-2026-0019](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0019;hb=HEAD) names release2.44 fix **6f9b2bfa500bf5d1cff5d990adfff4b71298dadd**. Its patch reverse-applies exactly without fuzz/offset. Exact tree registers `iconvdata/tst-jisx0213-progress.c` (BZ34556/34568). |
| 207 / CVE-2026-80489 | `iconvdata/euc-jisx0213.c:227–232`: corresponding pending-character branch explicitly clears `*statep = 0`, eliminating repeated output without input progress. | Official [GLIBC-SA-2026-0020](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0020;hb=HEAD) names2.44 fix cb61572e and master fix **4dafa087ff5fe7df45bd37dc727e988da6b8c935**. Downloaded master patch reverse-applies exactly without fuzz/offset. Same registered progress test covers this encoding. |
| 266 / CVE-2026-8674 | Resolver search-list handling fixed in `resolv/resolv_conf.c`, with corresponding initialization regression. | DNS reviewer fetched official **506ea57086bfb9ce3daff1c14246a1cb532aba0a** patch; this reviewer independently repeated exact reverse-apply check against34106: success, no fuzz/offset. |
| 22 / CVE-2026-5435 | Deprecated DNS formatter bounds handling fixed in `resolv/ns_print.c`. | Official patch **ca44a6609c29a683b03575fa035c6d17aa591e72** reverse-applies exactly to34106; independently repeated, no fuzz/offset. |
| 25 / CVE-2026-6238 | Deprecated DNS formatter RDATA validation fixed in `resolv/ns_print.c`. | Official patch **a7b60d23bbb56eaef59f4962e4140062e552600a** reverse-applies exactly to34106; independently repeated, no fuzz/offset. |

The four first rows are direct implementation-and-regression source proofs; their individual fixing commit IDs were not recovered in this review. The remaining six have exact official upstream-patch inclusion proofs. No inference that merely “2.44 is greater than2.41” was used.

## Reproducible checks and hashes

For each official patch below, ran `patch --dry-run -R -p1 -i /tmp/file-scanner-glibc-CVE.patch` from the exact extracted source. All returned0, printed the expected source filenames, and reported **no fuzz or line offset**. Reverse dry run does not modify files. Verified each patch is nonempty before accepting success:

| CVE suffix | Patch bytes | Patched files |
|---|---:|---|
| 8674 | 4886 | `resolv/resolv_conf.c`, `resolv/tst-resolv-res_init-skeleton.c` |
| 5435 | 3584 | `resolv/ns_print.c` |
| 6238 | 2138 | `resolv/ns_print.c` |
| 19542 | 3299 | `misc/tsearch.c` |
| 77117 | 984 | `iconvdata/shift_jisx0213.c` |
| 80489 | 903 | `iconvdata/euc-jisx0213.c` |

| Exact source file | SHA-256 |
|---|---|
| `posix/wordexp.c` | `f283a59b71ebe31cd2ee9724239fa8aaa4159fbed5825f8e168c3bd6ea9d06b7` |
| `libio/fileops.c` | `26458cc34ef1f436c8d93a737315376362ff957d8911192ed1f1c29976c76dcc` |
| `stdlib/strfmon_l.c` | `5ad7ee1b3c14629bb5467666421ff48e760dfbd00f2cdc870fd90fef45cc25fe` |
| `misc/tsearch.c` | `2f1b227c71c27f8842d349163b8a734214c7cb4575a599cf7e63dc0c6561fb24` |
| `iconvdata/shift_jisx0213.c` | `a507752162900c47f085957e6d9ca1949b553c29cc5cdfbdea13e7ab2bae4dd3` |
| `iconvdata/euc-jisx0213.c` | `4940d974aadefab6b318724576b048b8d903db34879959f962994c4051977f09` |

This source review links recipe2.44-r8 to the implemented security fixes. The independently recorded image package inventories, exact-image scans and runtime functional tests supply the separate artifact/deployment evidence. Parent is also collecting versioned Chainguard advisory records; the absence of entries in the legacy Wolfi `glibc` advisory file alone is neither a fix proof nor a blocker once exact implementation is verified.
