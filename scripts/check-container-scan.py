#!/usr/bin/env python3
"""Validate a complete Trivy image report and gate every vulnerability severity."""

import argparse
import json
from pathlib import Path
import re
import sys


class ScanError(ValueError):
    """The scan is incomplete, targets the wrong image, or reports vulnerabilities."""


def inspect_report(report, architecture, *, image_id=None, reference=None):
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ScanError("Expected a Trivy schema 2 report")
    if report.get("ArtifactType") != "container_image":
        raise ScanError("Expected a container image scan")
    metadata = report.get("Metadata", {})
    if image_id:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ScanError("Expected an immutable image config ID")
        if metadata.get("ImageID") != image_id:
            raise ScanError("Scan does not describe the loaded image artifact")
    elif reference:
        if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", reference):
            raise ScanError("Expected an immutable image manifest reference")
        if report.get("ArtifactName") != reference:
            raise ScanError("Scan does not describe the published build digest")
    else:
        raise ScanError("Expected image identity is required")
    if metadata.get("ImageConfig", {}).get("architecture") != architecture:
        raise ScanError(f"Scan must describe the {architecture} image")
    os_metadata = metadata.get("OS", {})
    if not os_metadata.get("Family") or os_metadata.get("EOSL"):
        raise ScanError("A supported runtime OS must be identified")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ScanError("Missing package scan results")
    if not any(isinstance(item, dict) and item.get("Class") == "os-pkgs"
               and isinstance(item.get("Packages"), list) and item["Packages"]
               for item in results):
        raise ScanError("Missing OS package inventory; an empty report is not a clean image")
    labels = metadata.get("ImageConfig", {}).get("config", {}).get("Labels", {})
    if labels.get("org.opencontainers.image.source") != "https://github.com/ThreatFlux/file-scanner":
        raise ScanError("Expected the scanner application image, not its clean base")
    if not any(isinstance(item, dict) and item.get("Class") == "lang-pkgs"
               and item.get("Type") == "cargo"
               and item.get("Target", "").lstrip("/") == "usr/share/doc/file-scanner/sbom.cdx.json"
               and isinstance(item.get("Packages"), list) and item["Packages"]
               for item in results):
        raise ScanError("Missing application Cargo SBOM inventory")
    findings = []
    for result in results:
        if not isinstance(result, dict):
            raise ScanError("Invalid package scan result")
        for package in result.get("Packages", []):
            if (not isinstance(package, dict) or not isinstance(package.get("Name"), str)
                    or not package["Name"] or not isinstance(package.get("Version"), str)
                    or not package["Version"]):
                raise ScanError("Incomplete package identity/version inventory")
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise ScanError("Invalid vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict) or not vulnerability.get("VulnerabilityID"):
                raise ScanError("Invalid vulnerability record")
            severity = vulnerability.get("Severity")
            if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ScanError("Missing or unrecognized vulnerability severity")
            findings.append(f"{vulnerability['VulnerabilityID']} ({severity})")
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", required=True, choices=["amd64", "arm64"])
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--image-id", help="Config digest from the loaded PR image artifact")
    identity.add_argument("--reference", help="Immutable registry reference from the build output")
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate completeness before converting/uploading all findings")
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        findings = inspect_report(json.loads(args.report.read_text()), args.architecture,
                                  image_id=args.image_id, reference=args.reference)
        if findings and not args.validate_only:
            raise ScanError("Container vulnerabilities: " + ", ".join(findings))
    except (OSError, ValueError, AttributeError, TypeError) as error:
        print(f"Container security check failed: {error}", file=sys.stderr)
        return 1
    print(f"Validated {args.architecture} package inventory: {len(findings)} vulnerabilities")
    return 0


if __name__ == "__main__":
    sys.exit(main())
