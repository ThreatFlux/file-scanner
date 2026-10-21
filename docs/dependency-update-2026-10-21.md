# Stable dependency rollup — 2026-10-21

Security follow-up: the [implemented runtime remediation and completed FP dispositions](security/security-alert-remediation-2026-10-21.md) supersede the initial runtime pin and pending-action statements below. The dependency rollup now also includes the stable libz-sys native security backport.

Base: `a34604292e7060f45d3c6f10b392c326afe2ead1` (`main`). Rust build toolchain: **1.99.1**. MSRV is a separate compatibility floor, not the build toolchain.

Latest non-yanked stable direct crate releases were verified against the [crates.io sparse index](https://index.crates.io/config.json); prerelease suffixes are excluded, build metadata is preserved in the inventory below. Both independently locked Cargo projects are updated. Transitive versions follow upstream compatibility constraints rather than forcing incompatible major versions. The YARA-X vendor patch keeps stable Wasmtime and RSA; its own dependency versions follow that upstream release plus the documented security patch.

| Direct crate | Latest stable | Release timestamp |
|---|---|---|
| `addr2line` | `0.27.1` | 2026-08-01T08:57:27Z |
| `anyhow` | `1.0.104` | 2026-07-18T20:59:37Z |
| `assert_cmd` | `2.2.2` | 2026-05-11T14:12:46Z |
| `assert_fs` | `1.1.4` | 2026-05-26T16:15:40Z |
| `async-trait` | `0.1.92` | 2026-08-08T07:10:35Z |
| `axum` | `0.8.9` | 2026-04-14T07:55:20Z |
| `base64` | `0.23.1` | 2026-08-04T12:34:31Z |
| `blake3` | `1.8.7` | 2026-08-20T09:09:56Z |
| `capstone` | `0.14.0` | 2026-01-04T09:20:17Z |
| `cfb` | `0.15.0` | 2026-09-18T22:22:45Z |
| `chrono` | `0.4.45` | 2026-06-04T12:16:42Z |
| `clap` | `4.6.7` | 2026-09-14T18:40:28Z |
| `criterion` | `0.8.2` | 2026-02-04T10:43:03Z |
| `dashmap` | `6.2.1` | 2026-05-17T21:28:34Z |
| `dirs` | `7.0.0` | 2026-09-05T17:32:15Z |
| `edit-distance` | `2.2.2` | 2025-10-03T10:58:24Z |
| `encoding_rs` | `0.8.42` | 2026-09-24T14:45:32Z |
| `filetime` | `0.2.29` | 2026-05-12T22:38:22Z |
| `flate2` | `1.1.10` | 2026-08-28T04:35:22Z |
| `futures-util` | `0.3.34` | 2026-08-11T12:13:19Z |
| `git2` | `0.21.0` | 2026-05-18T16:06:09Z |
| `goblin` | `0.10.7` | 2026-05-28T02:41:25Z |
| `hex` | `0.4.3` | 2021-03-03T10:48:58Z |
| `hyper` | `1.12.0` | 2026-10-06T15:57:18Z |
| `libc` | `0.2.191` | 2026-10-16T22:56:46Z |
| `md-5` | `0.11.0` | 2026-03-27T14:59:39Z |
| `memmap2` | `0.9.11` | 2026-06-22T16:04:03Z |
| `mockall` | `0.15.0` | 2026-06-28T21:00:17Z |
| `mockito` | `1.7.2` | 2026-02-02T13:53:09Z |
| `object` | `0.40.0` | 2026-08-01T08:06:55Z |
| `once_cell` | `1.21.4` | 2026-03-12T10:59:52Z |
| `parking_lot` | `0.12.5` | 2025-10-03T23:34:14Z |
| `petgraph` | `0.8.3` | 2025-09-30T13:16:04Z |
| `predicates` | `3.1.4` | 2026-02-11T14:41:47Z |
| `pretty_assertions` | `1.4.1` | 2024-09-15T13:11:03Z |
| `proptest` | `1.12.0` | 2026-10-10T18:18:05Z |
| `quick-xml` | `0.42.0` | 2026-08-22T19:22:01Z |
| `rand` | `0.10.3` | 2026-09-20T06:37:47Z |
| `regex` | `1.13.1` | 2026-07-15T20:19:35Z |
| `reqwest` | `0.13.5` | 2026-09-08T20:55:26Z |
| `ring` | `0.17.14` | 2025-03-11T19:42:03Z |
| `rmcp` | `3.6.0` | 2026-10-20T05:53:35Z |
| `rstest` | `0.28.0` | 2026-10-18T19:37:56Z |
| `schemars` | `1.2.3` | 2026-10-12T20:30:07Z |
| `serde` | `1.0.229` | 2026-07-18T23:05:13Z |
| `serde_json` | `1.0.154` | 2026-10-11T15:31:46Z |
| `serial_test` | `4.0.1` | 2026-07-25T20:27:56Z |
| `sha2` | `0.11.1` | 2026-10-12T18:58:22Z |
| `strsim` | `0.11.1` | 2024-04-02T22:18:09Z |
| `tar` | `0.4.46` | 2026-05-18T19:12:11Z |
| `tempfile` | `3.27.0` | 2026-03-11T00:20:04Z |
| `test-case` | `3.4.0` | 2026-09-23T13:06:09Z |
| `thiserror` | `2.0.21` | 2026-09-23T20:24:07Z |
| `threatflux-binary-analysis` | `0.3.1` | 2026-10-06T16:26:49Z |
| `threatflux-cache` | `0.2.1` | 2026-10-06T17:09:24Z |
| `threatflux-hashing` | `1.7.1` | 2026-10-06T16:05:03Z |
| `threatflux-string-analysis` | `0.2.3` | 2026-10-06T17:20:17Z |
| `threatflux-threat-detection` | `0.2.3` | 2026-10-06T18:02:56Z |
| `tokio` | `1.54.0` | 2026-10-19T16:33:48Z |
| `tokio-stream` | `0.1.19` | 2026-07-22T08:19:01Z |
| `tokio-test` | `0.4.6` | 2026-09-25T09:30:40Z |
| `toml` | `1.1.8+spec-1.1.0` | 2026-10-09T02:46:31Z |
| `tower` | `0.5.3` | 2026-01-12T18:43:05Z |
| `tower-http` | `0.7.1` | 2026-08-31T14:49:25Z |
| `tracing` | `0.1.44` | 2025-12-18T14:26:12Z |
| `url` | `2.5.8` | 2026-01-05T22:14:31Z |
| `utoipa` | `6.0.0` | 2026-09-22T22:30:17Z |
| `utoipa-redoc` | `7.0.0` | 2026-09-22T22:31:11Z |
| `utoipa-swagger-ui` | `10.0.2` | 2026-10-20T16:27:11Z |
| `uuid` | `1.28.0` | 2026-10-10T00:02:40Z |
| `walkdir` | `2.5.0` | 2024-03-01T17:55:09Z |
| `wiremock` | `0.6.5` | 2025-08-24T11:50:14Z |
| `yara-x` | `1.22.0` | 2026-10-20T12:15:36Z |
| `zip` | `9.0.5` | 2026-10-17T18:45:16Z |

YAML replacement: [`serde-saphyr` 2.0.0](https://index.crates.io/se/rd/serde-saphyr), verified latest non-yanked stable, replaces deprecated `serde_yaml`.

## Tooling and container pins

Actions retain immutable SHA pins with release comments. Updated versions include CodeQL 4.39.0, upload-artifact 7.0.2, download-artifact 8.0.2, install-action 2.87.29, TruffleHog 3.99.3, and the reusable Rust workflow 0.7.8. Build tools include Buildx 0.38.1, BuildKit 0.34.1, Trivy 0.76.0, Cosign 3.1.4, Semgrep 1.182.0, zizmor 1.31.1 and Commitizen 4.19.2. Other pins were checked and already current.

The Rust 1.99.1 trixie builder index is `sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a`; the distroless Debian 13 nonroot runtime index is `sha256:b7e81cb1af38d9345680e68bcf564d388f96304e25222030fc8c051faf8565b3`.

## Compatibility patches and audit

Latest upstream YARA-X uses prerelease RSA; the refreshed [vendor patch](../vendor/README.md) keeps stable RSA 0.9.10 with its existing public-key-only advisory exception and latest stable Wasmtime 49.0.4. Stable crypto compatibility series coexist with current digest versions. The graph contains no prerelease package versions.

Latest upstream `threatflux-binary-analysis` 0.3.1 still resolves ZIP 8.6.0, producing RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369 in the fresh audit. Its minimal [ZIP patch](../vendor/threatflux-binary-analysis-0.3.1.patch) moves that dependency to 9.0.5 and adapts fallible filename reads. Root and package-security readers likewise propagate filename decoding failures. There are no new advisory exemptions. A separate audit run without repository ignore configuration reports only the retained RSA advisory RUSTSEC-2023-0071; `scripts/check-rsa-exception.py` verifies the sole caller is the source-pinned public-key verification implementation. The deny gate also identified unmaintained `unsafe-libyaml`; both projects now use maintained `serde-saphyr` 2.0.0 under the existing `serde_yaml` source alias, removing `serde_yaml` and `unsafe-libyaml` from both lockfiles. Serialization remains YAML, but emitter formatting may change. Existing YAML roundtrip tests verify data compatibility. Only the pre-existing bincode maintenance exception remains; latest stable versions do not imply maintained upstream projects.

Root Cargo patches apply to source builds, release binaries and containers. Cargo does **not** propagate them to downstream library consumers or published packages; see the vendor provenance and distribution notes before relying on this exact stable graph from crates.io.

## Superseded PRs

This rollup includes or supersedes #244, #245, #246, #247, #249, #250, #251, #252, #253, #254, #255, #256, #258, #259, #260, #261, #262, #263, #264, #265 and #266. Some versions exceed the individual PR versions because newer stable releases are available.

## Security review

See [Dependabot review](security/dependabot-review-2026-10-21.md) and [code-scanning review](security/code-scanning-review-2026-10-21.md) for alert-by-alert evidence, TP/FP qualifications and remediation plans. No alerts were dismissed and no Jira tickets were created. Updating dependencies does not assert that OS package alerts are fixed; rebuilt container scans must establish that independently.

## Validation

- Both direct dependency outdated checks report no upgrades (the YAML alias is verified separately against the serde-saphyr sparse index). Both lockfiles contain no prerelease package versions.
- Final root and standalone MSRV 1.97.1 all-feature/all-target checks pass.
- Final standalone Rust 1.99.1 all-target checks and clippy pass. Full standalone tests pass unchanged in a pinned Linux container: 25 tests with default features and 25 with no default features. The host blocks one malicious fixture with EPERM; this is reproduced on the host and passes in Linux.
- Audit and deny pass under existing reviewed RSA/bincode policy. A no-ignore audit identifies only RUSTSEC-2023-0071.
- Reviewed CodeQL source guard and 21 regressions, workflow validation, Docker build checks, and RSA/Java compatibility regressions pass.
- Final stable-toolchain root lint, build, documentation and benchmark checks pass. The initial full scanner suite passed 2,572 tests (3 ignored); the final-graph rerun encountered the same host EPERM on a deliberately malicious npm fixture. Linux verification and the final complete-suite result are recorded in the pull request validation notes. `make ci-local` stops on that host fixture error, so this is not presented as a fully green host CI run.
- The final no-fail-fast scanner rerun completed all 51 suites: 2,570 passed, 3 ignored, with two failures. One is the host EPERM fixture above; the other is the unchanged cache persistence test, which assumes 500 ms is enough for asynchronous saves under load. Its exact isolated rerun passes. These limitations are retained in the PR validation notes rather than treating retries as an entirely green host run.
