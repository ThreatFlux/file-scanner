#!/usr/bin/env python3
"""Annotate nine source-pinned forensic hash false positives; preserve all others."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tomllib


POLICY_DIGEST = "6fdda0428ebfe5192bc5961265ae4faf232108d588678583a3c69196baa4aba7"
SOURCE_TOKENS = (
    "thumbprint", "pearson_hash", "TlshBuilder", "Certificate",
    "CertificateChain", "AuthenticodeSignature", "X509CertificateParser",
)
SKIP_PATHS = {
    ".git", "target", "threatflux-threat-detection/target",
    "threatflux-package-security/target",
}


class ReviewError(Exception):
    """A changed review assumption prevents annotation and filtering."""


def canonical_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_policy(root):
    path = root / ".github/codeql-reviewed-findings.json"
    policy = json.loads(path.read_text())
    if canonical_digest(policy) != POLICY_DIGEST:
        raise ReviewError("Reviewed manifest changed; an explicit new review is required")
    return policy


def source_inventory(root):
    # Substrings also cover generated getters/setters and inferred-type callers.
    pattern = re.compile("|".join(SOURCE_TOKENS), re.IGNORECASE)
    inventory = {}
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = sorted(name for name in subdirectories
                                  if (Path(directory) / name).relative_to(root).as_posix() not in SKIP_PATHS)
        for filename in sorted(filenames):
            if not filename.endswith(".rs"):
                continue
            path = Path(directory) / filename
            if pattern.search(path.read_text()):
                inventory[path.relative_to(root).as_posix()] = file_digest(path)
    return inventory


def check_dependency_graph(root, policy):
    lock = tomllib.loads((root / "Cargo.lock").read_text())
    for name, version in policy["dependency_versions"].items():
        packages = [item for item in lock["package"] if item["name"] == name]
        if len(packages) != 1 or packages[0]["version"] != version:
            raise ReviewError(f"Reviewed dependency changed: {name} {version}")
        if name == "yara-x" and "source" in packages[0]:
            raise ReviewError("Reviewed YARA-X must resolve to the local vendored package")
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    patch = manifest["patch"]["crates-io"]["yara-x"]
    if patch != {"path": policy["vendor"]["path"]}:
        raise ReviewError("Reviewed YARA-X path override changed")
    vendor = tomllib.loads((root / policy["vendor"]["path"] / "Cargo.toml").read_text())
    if vendor["package"]["version"] != policy["vendor"]["version"]:
        raise ReviewError("Reviewed vendored YARA-X version changed")
    target = vendor["target"]['cfg(not(target_family = "wasm"))']
    if target["dependencies"]["wasmtime"]["version"] != policy["dependency_versions"]["wasmtime"]:
        raise ReviewError("Reviewed vendored Wasmtime requirement changed")


def check_sources(root, policy):
    actual = source_inventory(root)
    expected = policy["token_source_inventory"]
    if actual != expected:
        changed = sorted(path for path in actual.keys() | expected.keys()
                         if actual.get(path) != expected.get(path))
        raise ReviewError("Reviewed caller/source inventory changed: " + ", ".join(changed))
    for relative, digest in policy["call_path_sha256"].items():
        if file_digest(root / relative) != digest:
            raise ReviewError("Reviewed verification call path changed: " + relative)
    check_dependency_graph(root, policy)


def normalized_region(region):
    if not isinstance(region, dict):
        return region
    start = region.get("startLine")
    # SARIF 2.1.0 section 3.30.7 defaults an omitted endLine to startLine.
    if "endLine" not in region and type(start) is int and start > 0:
        return {**region, "endLine": start}
    return region


def result_key(result):
    locations = result.get("locations", [])
    if len(locations) != 1:
        return None
    physical = locations[0].get("physicalLocation", {})
    return canonical_digest({
        "rule_id": result.get("ruleId"),
        "path": physical.get("artifactLocation", {}).get("uri"),
        "region": normalized_region(physical.get("region")),
        "message": result.get("message", {}).get("text"),
    })


def annotate_documents(documents, policy):
    reviewed = {canonical_digest(item["match"]): item for item in policy["reviewed_findings"]}
    annotated = copy.deepcopy(documents)
    seen = set()
    accepted = []
    for document in annotated.values():
        for run in document.get("runs", []):
            for result in run.get("results", []):
                key = result_key(result)
                finding = reviewed.get(key)
                if finding is None:
                    continue
                if key in seen:
                    raise ReviewError("Duplicate reviewed finding: " + finding["id"])
                seen.add(key)
                result.setdefault("suppressions", []).append({
                    "kind": "external", "status": "accepted",
                    "justification": finding["justification"],
                })
                accepted.append({"id": finding["id"], "match": finding["match"],
                                 "justification": finding["justification"]})
    return annotated, accepted, seen


def filter_documents(documents, accepted_keys):
    filtered = copy.deepcopy(documents)
    for document in filtered.values():
        for run in document.get("runs", []):
            run["results"] = [result for result in run.get("results", [])
                              if result_key(result) not in accepted_keys]
    return filtered


def result_count(documents):
    return sum(len(run.get("results", [])) for document in documents.values()
               for run in document.get("runs", []))


def input_files(args):
    directories = [args.input.resolve(), args.output.resolve(), args.annotated.resolve()]
    if len(set(directories)) != len(directories):
        raise ReviewError("Input, upload output, and annotated output must be distinct")
    if any(left in right.parents for left in directories for right in directories if left != right):
        raise ReviewError("SARIF directories must not contain each other")
    files = sorted(args.input.rglob("*.sarif"))
    if not files:
        raise ReviewError("No raw SARIF inputs found")
    return files


def preserve_raw_inputs(args, files):
    for source in files:
        relative = source.relative_to(args.input)
        for directory in [args.output, args.annotated]:
            destination = directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)


def write_documents(directory, documents):
    for relative, document in documents.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + "\n")


def print_summary(report):
    summary = (f"CodeQL reviewed findings: {report['status']}; "
               f"reviewed false positives omitted from upload: {report['omitted_count']}; "
               f"other results retained: {report.get('retained_count', 'unknown')}.")
    print(summary)
    if report.get("error"):
        print(report["error"], file=sys.stderr)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(path).open("a") as summary_file:
            summary_file.write(summary + "\n")
            if report.get("error"):
                summary_file.write("Guard failure: " + report["error"] + "\n")


def process_directory(root, args):
    report = {"status": "blocked", "omitted_count": 0, "accepted_findings": [],
              "policy_digest": POLICY_DIGEST,
              "note": "Raw evidence retains every result; only exact reviewed false positives may be omitted from the GitHub upload."}
    try:
        files = input_files(args)
        preserve_raw_inputs(args, files)
        documents = {path.relative_to(args.input).as_posix(): json.loads(path.read_text()) for path in files}
        report["raw_count"] = result_count(documents)
        report["retained_count"] = report["raw_count"]
        policy = load_policy(root)
        check_sources(root, policy)
        annotated, accepted, keys = annotate_documents(documents, policy)
        filtered = filter_documents(documents, keys)
        write_documents(args.annotated, annotated)
        write_documents(args.output, filtered)
        report.update(status="passed", omitted_count=len(accepted),
                      accepted_findings=accepted, retained_count=result_count(filtered),
                      source_inventory_count=len(policy["token_source_inventory"]))
    except (ReviewError, OSError, ValueError, KeyError, TypeError) as error:
        report["error"] = str(error)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print_summary(report)
    return 0 if report["status"] == "passed" else 1


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-sources", action="store_true")
    for name in ["input", "output", "annotated", "report"]:
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args()
    if not args.check_sources and any(getattr(args, name) is None for name in ["input", "output", "annotated", "report"]):
        parser.error("--input, --output, --annotated, and --report are required")
    return args


def main():
    args = parse_arguments()
    root = Path(__file__).resolve().parent.parent
    if not args.check_sources:
        return process_directory(root, args)
    try:
        policy = load_policy(root)
        check_sources(root, policy)
    except (ReviewError, OSError, ValueError, KeyError, TypeError) as error:
        print("CodeQL reviewed source guard failed: " + str(error), file=sys.stderr)
        return 1
    print("CodeQL reviewed source and dependency guard passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
