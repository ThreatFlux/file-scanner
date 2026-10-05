"""Regressions pin PR236 API analysis1891303529 and raw CLI run37274884642 SARIF."""

import argparse
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "codeql_review", REPOSITORY / "scripts/codeql-reviewed-findings.py"
)
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)
FIXTURE = REPOSITORY / "scripts/codeql-reviewed-findings-fixture.sarif"
RAW_FIXTURE = REPOSITORY / "scripts/codeql-reviewed-findings-raw-25c41d9.sarif.gz"


class ReviewedFindingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.summary = self.base / "summary.md"
        summary_environment = mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(self.summary)})
        summary_environment.start()
        self.addCleanup(summary_environment.stop)
        self.root = self.base / "repository"
        self.policy = REVIEW.load_policy(REPOSITORY)
        paths = set(self.policy["token_source_inventory"])
        paths.update(self.policy["call_path_sha256"])
        paths.update(["Cargo.toml", "Cargo.lock", ".github/codeql-reviewed-findings.json"])
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPOSITORY / relative, destination)
        self.args = argparse.Namespace(input=self.base / "raw", output=self.base / "upload",
                                       annotated=self.base / "annotated", report=self.base / "report.json")
        self.args.input.mkdir()
        self.sarif = json.loads(FIXTURE.read_text())
        self.save_input(self.sarif)

    def save_input(self, document):
        (self.args.input / "rust.sarif").write_text(json.dumps(document))

    def run_review(self):
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            status = REVIEW.process_directory(self.root, self.args)
        report = json.loads(self.args.report.read_text())
        upload = json.loads((self.args.output / "rust.sarif").read_text())
        annotated = json.loads((self.args.annotated / "rust.sarif").read_text())
        return status, report, upload, annotated

    def assert_blocked_without_omissions(self):
        status, report, upload, annotated = self.run_review()
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["omitted_count"], 0)
        self.assertEqual(upload, self.sarif)
        self.assertEqual(annotated, self.sarif)
        self.assertIn("blocked", self.stdout.getvalue())
        self.assertTrue(self.stderr.getvalue().strip())

    def test_actual_sarif_is_annotated_and_retains_rule_extensions(self):
        digest = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        self.assertEqual(digest, "51f52243dbf414e478478854a33e9eaa37427a5d6c6a66592b96806aa5e0f3fa")
        status, report, upload, annotated = self.run_review()
        self.assertEqual(status, 0)
        self.assertEqual(report["raw_count"], 9)
        self.assertEqual(report["omitted_count"], 9)
        self.assertEqual(report["retained_count"], 0)
        self.assertIn("false positives omitted from upload: 9", self.stdout.getvalue())
        self.assertIn("false positives omitted from upload: 9", self.summary.read_text())
        self.assertEqual(self.stderr.getvalue(), "")
        self.assertEqual(upload["runs"][0]["tool"], self.sarif["runs"][0]["tool"])
        self.assertIn("extensions", upload["runs"][0]["tool"])
        self.assertEqual(upload["runs"][0]["results"], [])
        for result in annotated["runs"][0]["results"]:
            suppression = result["suppressions"][-1]
            self.assertEqual(suppression["kind"], "external")
            self.assertEqual(suppression["status"], "accepted")
            self.assertIn("Reviewed false positive:", suppression["justification"])

    def test_hosted_raw_sarif_matches_without_changing_raw_regions(self):
        raw = gzip.decompress(RAW_FIXTURE.read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "156d98c8a2431b19151976ffb50e17a5f3ac6bb9bd0ac1983837beb8d9adc033")
        self.sarif = json.loads(raw)
        (self.args.input / "rust.sarif").write_bytes(raw)
        status, report, upload, annotated = self.run_review()
        self.assertEqual(status, 0)
        self.assertEqual((report["raw_count"], report["omitted_count"], report["retained_count"]), (9, 9, 0))
        self.assertEqual((self.args.input / "rust.sarif").read_bytes(), raw)
        self.assertEqual(upload["runs"][0]["results"], [])
        for original, reviewed in zip(self.sarif["runs"][0]["results"], annotated["runs"][0]["results"]):
            self.assertEqual(reviewed["locations"], original["locations"])
            self.assertEqual(reviewed["suppressions"][-1]["status"], "accepted")

    def assert_unmatched_region(self, region):
        finding = copy.deepcopy(self.sarif["runs"][0]["results"][0])
        finding["locations"][0]["physicalLocation"]["region"] = region
        documents = {"rust.sarif": {"runs": [{"results": [finding]}]}}
        annotated, accepted, keys = REVIEW.annotate_documents(documents, self.policy)
        self.assertEqual(accepted, [])
        self.assertEqual(annotated, documents)
        self.assertEqual(REVIEW.filter_documents(documents, keys), documents)

    def test_explicit_end_line_is_never_defaulted(self):
        region = self.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        for value in [None, "305", 306, 0, True, 305.0]:
            with self.subTest(endLine=value):
                changed = {**region, "endLine": value}
                self.assertEqual(REVIEW.normalized_region(changed), changed)
                self.assert_unmatched_region(changed)

    def test_missing_end_line_requires_positive_integer_start_line(self):
        region = self.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        for value in [None, True, "305", 0, -1, 305.0]:
            with self.subTest(startLine=value):
                changed = {key: item for key, item in region.items() if key != "endLine"}
                changed["startLine"] = value
                self.assertEqual(REVIEW.normalized_region(changed), changed)
                self.assert_unmatched_region(changed)
        missing = {key: item for key, item in region.items() if key not in ["startLine", "endLine"]}
        self.assertEqual(REVIEW.normalized_region(missing), missing)
        self.assert_unmatched_region(missing)

    def test_defaulted_region_preserves_every_other_field(self):
        region = self.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        raw = {key: value for key, value in region.items() if key != "endLine"}
        self.assertEqual(REVIEW.normalized_region(raw), region)
        self.assertNotIn("endLine", raw)
        for changed in [{**raw, "endColumn": 23}, {**raw, "byteOffset": 0},
                        {key: value for key, value in raw.items() if key != "startColumn"}, None]:
            with self.subTest(region=changed):
                self.assert_unmatched_region(changed)

    def test_raw_and_canonical_duplicates_block_every_omission(self):
        raw = json.loads(gzip.decompress(RAW_FIXTURE.read_bytes()))
        self.sarif["runs"][0]["results"].append(raw["runs"][0]["results"][0])
        self.save_input(self.sarif)
        self.assert_blocked_without_omissions()

    def test_new_sensitive_hash_finding_survives_unchanged(self):
        new = copy.deepcopy(self.sarif["runs"][0]["results"][-1])
        new["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "src/new_authentication.rs"
        new["message"]["text"] = "Sensitive password data is hashed with SHA1."
        self.sarif["runs"][0]["results"].append(new)
        self.save_input(self.sarif)
        status, report, upload, annotated = self.run_review()
        self.assertEqual(status, 0)
        self.assertEqual(report["omitted_count"], 9)
        self.assertEqual(upload["runs"][0]["results"], [new])
        self.assertEqual(annotated["runs"][0]["results"][-1], new)

    def test_changed_tuple_fields_are_never_matched(self):
        for field in ["rule_id", "path", "region", "message"]:
            with self.subTest(field=field):
                finding = copy.deepcopy(self.sarif["runs"][0]["results"][0])
                if field == "rule_id":
                    finding["ruleId"] += "-new-query"
                elif field == "path":
                    finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] += ".new"
                elif field == "region":
                    finding["locations"][0]["physicalLocation"]["region"]["endColumn"] += 1
                else:
                    finding["message"]["text"] += " New data flow."
                documents = {"rust.sarif": {"runs": [{"results": [finding]}]}}
                annotated, accepted, keys = REVIEW.annotate_documents(documents, self.policy)
                self.assertEqual(accepted, [])
                self.assertEqual(annotated, documents)
                self.assertEqual(REVIEW.filter_documents(documents, keys), documents)

    def test_changed_existing_verification_call_path_blocks_every_omission(self):
        path = self.root / "vendor/yara-x-1.21.0/src/modules/utils/crypto.rs"
        path.write_text(path.read_text() + "\n// Changed verification implementation.\n")
        self.assert_blocked_without_omissions()

    def test_added_first_party_caller_blocks_every_omission(self):
        path = self.root / "src/new_authentication.rs"
        path.parent.mkdir(exist_ok=True)
        path.write_text('fn authenticate(cert: Certificate) -> bool { cert.thumbprint == "trusted" }\n')
        self.assert_blocked_without_omissions()

    def test_added_vendor_caller_blocks_every_omission(self):
        path = self.root / "vendor/yara-x-1.21.0/src/new_authentication.rs"
        path.write_text('fn authenticate(cert: Certificate) -> bool { cert.thumbprint == "trusted" }\n')
        self.assert_blocked_without_omissions()

    def test_added_accessor_caller_without_certificate_type_blocks_omissions(self):
        path = self.root / "src/new_authentication.rs"
        path.parent.mkdir(exist_ok=True)
        path.write_text('fn authenticate(item: &mut Parsed) -> bool { item.take_thumbprint() == "trusted" }\n')
        self.assert_blocked_without_omissions()

    def test_inventory_matches_accessors_and_case_changes(self):
        path = self.root / "src/new_accessor.rs"
        path.parent.mkdir(exist_ok=True)
        for call in ["get_thumbprint", "set_thumbprint", "take_thumbprint", "take_ThumbPrint"]:
            with self.subTest(call=call):
                path.write_text(f"fn accessor(item: &mut Parsed) {{ item.{call}(); }}\n")
                self.assertIn("src/new_accessor.rs", REVIEW.source_inventory(self.root))

    def test_source_directories_named_like_caches_are_scanned(self):
        for name in ["target", "node_modules", ".venv"]:
            with self.subTest(directory=name):
                path = self.root / "src" / name / "new_authentication.rs"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fn accessor(item: &mut Parsed) { item.take_thumbprint(); }\n')
                with self.assertRaises(REVIEW.ReviewError):
                    REVIEW.check_sources(self.root, self.policy)
                path.unlink()

    def test_missing_reviewed_source_blocks_every_omission(self):
        (self.root / "vendor/yara-x-1.21.0/src/modules/utils/asn1.rs").unlink()
        self.assert_blocked_without_omissions()

    def test_duplicate_reviewed_finding_blocks_every_omission(self):
        results = self.sarif["runs"][0]["results"]
        results.append(copy.deepcopy(results[0]))
        self.save_input(self.sarif)
        self.assert_blocked_without_omissions()

    def test_manifest_expansion_blocks_every_omission(self):
        path = self.root / ".github/codeql-reviewed-findings.json"
        self.policy["reviewed_findings"].append(copy.deepcopy(self.policy["reviewed_findings"][0]))
        path.write_text(json.dumps(self.policy))
        self.assert_blocked_without_omissions()

    def test_changed_yara_graph_blocks_every_omission(self):
        path = self.root / "Cargo.lock"
        text = path.read_text().replace('name = "yara-x"\nversion = "1.21.0"',
                                        'name = "yara-x"\nversion = "1.22.0"')
        path.write_text(text)
        self.assert_blocked_without_omissions()

    def test_query_improvement_may_remove_reviewed_findings(self):
        self.sarif["runs"][0]["results"] = []
        self.save_input(self.sarif)
        status, report, upload, annotated = self.run_review()
        self.assertEqual(status, 0)
        self.assertEqual(report["omitted_count"], 0)
        self.assertEqual(upload, self.sarif)
        self.assertEqual(annotated, self.sarif)

    def test_missing_input_fails_without_creating_filtered_results(self):
        (self.args.input / "rust.sarif").unlink()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = REVIEW.process_directory(self.root, self.args)
        self.assertEqual(status, 1)
        self.assertIn("No raw SARIF inputs found", stderr.getvalue())
        self.assertFalse(self.args.output.exists())
        self.assertEqual(json.loads(self.args.report.read_text())["omitted_count"], 0)


if __name__ == "__main__":
    unittest.main()
