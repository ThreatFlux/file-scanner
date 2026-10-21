# Dependabot security alert review — ThreatFlux/file-scanner

Follow-up: [completed dispositions and implemented remediation](security-alert-remediation-2026-10-21.md) supersede this initial review's pending actions.

Reviewed 2026-10-21 against default-branch commit `a34604292e7060f45d3c6f10b392c326afe2ead1` and the update checkout before its ongoing edits. Source: authenticated GitHub REST endpoint `GET /repos/ThreatFlux/file-scanner/dependabot/alerts?state=open` with pagination. The response contains **3 open alerts**, all medium severity. No alert was dismissed or modified. No Jira tickets were created.

## Classification and scope

**0 demonstrated runtime TPs; 3 FP for application exploitability, each a valid vulnerable-version match in a non-executed fixture.** This distinction matters: the package metadata really pins an affected version, so the alerts are not erroneous version detections. GitHub's dependency inventory labels each as a direct development dependency. The actual dependency is the `morgan: "1.10.0"` devDependency in a checked-in, extracted upstream Express 5.1.0 package at `test_npm_packages/package/package.json:75`. The repository is a Rust scanner; this directory is sample input, not its build or server application. No installed Morgan code or npm lockfile is checked in there.

Evidence supporting the non-reachable determination:

- `src/npm_analysis.rs:290-389` reads package metadata/tar entries and analyzes JSON. It does not execute npm, Node, package scripts, or Express/Morgan middleware.
- A targeted search of application source, tests, workflows, scripts, Dockerfile and Makefile found no `morgan` import, no reference to the `test_npm_packages` fixture path in build/test automation, and no npm installation of this manifest. `src/npm_vuln_db.rs:1063` only lists the string `morgan` as package intelligence.
- The package `include` allowlist in `Cargo.toml:152-159` ships Rust source, Cargo files, README, license and changelog; it excludes the fixture.
- `.dockerignore:16` excludes `test_npm_packages`; the runtime Docker stage copies only the compiled binary and SBOM. There is no Node/Express runtime deployment here.
- `test_npm_packages/express-5.1.0.tgz` contains the same upstream package as static archive input. Preserve archive provenance when changing any extracted metadata.

The verdict would change if a developer or future workflow ran `npm install` in the sample and deployed an HTTP server using its Morgan dependency. Lack of deployed reachability is based on repository evidence, not a claim that Morgan 1.10.0 is safe.

## Every open finding

| Alert | Advisory and issue | Affected versions / installed declaration | TP/FP and why | Proposed handling and validation |
|---|---|---|---|---|
| [#65](https://github.com/ThreatFlux/file-scanner/security/dependabot/65) | [GHSA-4vj7-5mj6-jm8m](https://github.com/expressjs/morgan/security/advisories/GHSA-4vj7-5mj6-jm8m), CVE-2026-5078: CR/LF log forging in `:remote-user` | `>=1.2.0, <=1.10.1`; first fixed `1.11.0`; sample pins `1.10.0` | **FP for runtime exploitability / TP inventory match.** Exploitation needs a running Morgan logger and attacker-controlled Basic-auth username. The scanner parses sample metadata and never constructs a Morgan logger. | No application security code fix is needed for current execution paths. If refreshing the sample metadata to eliminate vulnerable declarations, use stable Morgan `>=1.12.1` to cover all three advisories and document that the extracted copy differs from upstream. Alternatively remove the unused extracted duplicate while preserving the authenticated tarball fixture. Validate no runtime/build imports, package/container exclusion, and fresh dependency inventory after merge. If this sample becomes executable, add a CR/LF Basic-auth log-injection regression and upgrade before execution. |
| [#67](https://github.com/ThreatFlux/file-scanner/security/dependabot/67) | [GHSA-jxfw-x594-9x9m](https://github.com/expressjs/morgan/security/advisories/GHSA-jxfw-x594-9x9m), CVE-2026-15603: Unicode log separators | `<1.12.0`; first fixed `1.12.0`; sample pins `1.10.0` | **FP for runtime exploitability / TP inventory match.** Requires request-derived data being emitted by Morgan and downstream Unicode-aware log processing. This repository does not execute Morgan or emit its access logs. | Same shared fixture cleanup as #65. Do not stop at `1.11.0`, which remains affected. If used as an executable fixture in future, send headers/URL/auth values with U+0085, U+2028 and U+2029 and verify the logger emits one record with escaped separators. |
| [#68](https://github.com/ThreatFlux/file-scanner/security/dependabot/68) | [GHSA-9f6g-j8ch-79g4](https://github.com/expressjs/morgan/security/advisories/GHSA-9f6g-j8ch-79g4), CVE-2026-87859: unescaped quotes allow field forgery | `<1.12.1`; first fixed `1.12.1`; sample pins `1.10.0` | **FP for runtime exploitability / TP inventory match.** Requires running Morgan with combined/common/default or a custom quoted format and attacker-controlled token values. None of those logger execution paths exists here. | Same shared fixture cleanup as #65, with at least stable `1.12.1` (or newer verified stable) if updating. If runtime usage is introduced, test embedded `"` in user-agent, referrer, URL and Basic-auth username, including mixed backslash/quote input, and verify fields cannot be forged. |

## Plan for TPs if counting inventory findings

There are no demonstrated runtime TPs requiring an application patch. If repository policy treats every affected declared dependency as a TP regardless of reachability, **all three are fixed by one fixture maintenance change**, not three runtime fixes:

1. Decide explicitly whether `test_npm_packages/package` is an authentic upstream analysis fixture or maintained executable code. Current evidence supports the former.
2. Preferred provenance-preserving cleanup: remove the unused extracted duplicate, retain `express-5.1.0.tgz`, document its source/checksum and that it must only be analyzed as data. The scanner already supports `.tgz` directly. Do not hide an active application dependency via ignore rules.
3. If maintaining the extracted manifest, update Morgan to the latest verified stable version at least `1.12.1`, label the extracted tree as a modified fixture, and refresh any corresponding lockfile only if one is intentionally introduced. Do not run unknown package lifecycle scripts just to update metadata.
4. Validate fixture analysis still parses expected name/version/dependency fields, verify the published Rust package/container excludes fixtures, and confirm the GitHub dependency graph rescans the changed default branch and closes or removes the three version matches. Until that rescan, alerts remain open.
5. No blanket dismissals: any dismissal should name the exact fixture path, non-runtime evidence and conditions that invalidate the assessment. This review did not dismiss anything.

## Limits

Review covered all **open** alerts returned by GitHub at review time; previously fixed/dismissed alerts were outside the requested current remediation scope. The GitHub Dependabot endpoint reports no open Cargo alerts at this snapshot, which does not prove all Rust dependencies are vulnerability-free. Cargo audit/deny and full lockfile validation remain separate gates for the dependency rollup. No runtime exploit test was run because there is no Morgan execution path to exercise; executing an unrelated sample Express application would not establish scanner exploitability.
