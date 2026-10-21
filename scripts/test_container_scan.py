"""Container scans must fail closed and include every severity and platform."""

import contextlib
import copy
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "container_scan", Path(__file__).with_name("check-container-scan.py"))
SCAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCAN)
IMAGE_ID = "sha256:" + "a" * 64
REFERENCE = "ghcr.io/threatflux/file-scanner@sha256:" + "b" * 64


class ContainerScanTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "SchemaVersion": 2,
            "ArtifactType": "container_image",
            "ArtifactName": REFERENCE,
            "Metadata": {"ImageID": IMAGE_ID,
                         "ImageConfig": {"architecture": "amd64", "config": {"Labels": {
                             "org.opencontainers.image.source": "https://github.com/ThreatFlux/file-scanner"}}},
                         "OS": {"Family": "wolfi", "Name": "20230201"}},
            "Results": [{"Class": "os-pkgs", "Type": "wolfi",
                         "Packages": [{"Name": "glibc-2.44", "Version": "2.44-r8"}]},
                        {"Class": "lang-pkgs", "Type": "cargo",
                         "Target": "usr/share/doc/file-scanner/sbom.cdx.json",
                         "Packages": [{"Name": "threatflux-file-scanner", "Version": "0.3.7"}]}],
        }

    def inspect(self, report=None, architecture="amd64"):
        return SCAN.inspect_report(self.report if report is None else report, architecture, image_id=IMAGE_ID)

    def test_clean_inventory_for_each_supported_architecture(self):
        for architecture in ["amd64", "arm64"]:
            with self.subTest(architecture=architecture):
                self.report["Metadata"]["ImageConfig"]["architecture"] = architecture
                self.assertEqual(self.inspect(architecture=architecture), [])

    def test_cached_wrong_architecture_is_rejected(self):
        with self.assertRaises(SCAN.ScanError):
            self.inspect(architecture="arm64")

    def test_missing_or_unsupported_os_is_rejected(self):
        for os_metadata in [{}, {"Family": "wolfi", "EOSL": True}]:
            with self.subTest(os_metadata=os_metadata):
                self.report["Metadata"]["OS"] = os_metadata
                with self.assertRaises(SCAN.ScanError):
                    self.inspect()

    def test_empty_or_missing_package_scan_is_not_a_clean_image(self):
        for results in [None, [], [{}], [{"Class": "os-pkgs", "Packages": []}]]:
            with self.subTest(results=results):
                self.report["Results"] = results
                with self.assertRaises(SCAN.ScanError):
                    self.inspect()

    def test_wrong_artifact_or_schema_is_rejected(self):
        for field, value in [("SchemaVersion", 1), ("ArtifactType", "filesystem")]:
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.assertRaises(SCAN.ScanError):
                self.inspect(report)

    def test_all_severities_and_language_packages_are_preserved(self):
        for severity in ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            with self.subTest(severity=severity):
                report = copy.deepcopy(self.report)
                report["Results"].append({"Class": "lang-pkgs", "Vulnerabilities": [
                    {"VulnerabilityID": "TEST-ADVISORY", "Severity": severity}]})
                self.assertEqual(self.inspect(report),
                                 [f"TEST-ADVISORY ({severity})"])

    def test_malformed_vulnerability_data_is_rejected(self):
        for vulnerabilities in [None, {}, [{}], [{"VulnerabilityID": "TEST"}]]:
            with self.subTest(vulnerabilities=vulnerabilities):
                self.report["Results"][0]["Vulnerabilities"] = vulnerabilities
                with self.assertRaises(SCAN.ScanError):
                    self.inspect()

    def test_clean_base_without_scanner_sbom_is_rejected(self):
        self.report["Results"] = self.report["Results"][:1]
        with self.assertRaises(SCAN.ScanError):
            self.inspect()

    def test_wrong_image_identity_is_rejected(self):
        self.report["Metadata"]["ImageID"] = "sha256:" + "c" * 64
        with self.assertRaises(SCAN.ScanError):
            self.inspect()

    def test_immutable_published_reference_is_required(self):
        self.assertEqual(SCAN.inspect_report(self.report, "amd64", reference=REFERENCE), [])
        for reference in ["ghcr.io/threatflux/file-scanner:latest",
                          "ghcr.io/threatflux/file-scanner@sha256:" + "c" * 64]:
            with self.subTest(reference=reference), self.assertRaises(SCAN.ScanError):
                SCAN.inspect_report(self.report, "amd64", reference=reference)

    def test_missing_package_versions_are_rejected(self):
        del self.report["Results"][0]["Packages"][0]["Version"]
        with self.assertRaises(SCAN.ScanError):
            self.inspect()

    def test_upload_validation_keeps_findings_but_gate_fails(self):
        self.report["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "TEST-LOW", "Severity": "LOW"}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(json.dumps(self.report))
            args = ["--architecture", "amd64", "--image-id", IMAGE_ID, str(path)]
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(SCAN.main(["--validate-only", *args]), 0)
                self.assertEqual(SCAN.main(args), 1)
            self.assertIn("TEST-LOW (LOW)", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
