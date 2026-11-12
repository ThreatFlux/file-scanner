"""Publication replay regressions; executed by the existing hosted Quick Check."""

import importlib.util
import json
import pathlib
import secrets
import sys
import tempfile
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).parent / "container_publish_policy.py"
sys.path.insert(0, str(PATH.parent))
SPEC = importlib.util.spec_from_file_location("container_publish_policy", PATH)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
OLD = "a" * 40
NEW = "b" * 40
FAKE_TOKEN = secrets.token_hex(16)


def tag(name, sha):
    return {"name": name, "commit": {"sha": sha}}


class ContainerPublicationPolicy(unittest.TestCase):
    def test_current_main_keeps_main_tracking_aliases(self):
        self.assertEqual(
            POLICY.aliases("refs/heads/main", NEW, NEW, []),
            {"runtime": ["main", "latest"], "base": True},
        )

    def test_stale_main_retry_cannot_overwrite_newer_main(self):
        self.assertEqual(
            POLICY.aliases("refs/heads/main", OLD, NEW, []),
            {"runtime": [], "base": False},
        )

    def test_historical_tag_cannot_roll_stable_aliases_back(self):
        tags = [tag("v0.5.3", OLD), tag("v0.5.4", NEW)]
        self.assertEqual(
            POLICY.aliases("refs/tags/v0.5.3", OLD, NEW, tags),
            {"runtime": [], "base": False},
        )

    def test_latest_tag_uses_numeric_order_and_ignores_prereleases(self):
        tags = [tag("v0.5.9", OLD), tag("v0.5.10", NEW), tag("v1.0.0-rc.1", OLD)]
        self.assertEqual(
            POLICY.aliases("refs/tags/v0.5.10", NEW, NEW, tags),
            {"runtime": ["main", "latest", "0.5", "0"], "base": True},
        )

    def test_stable_tag_never_rewinds_main_tracking_aliases(self):
        self.assertEqual(
            POLICY.aliases("refs/tags/v0.5.4", OLD, NEW, [tag("v0.5.4", OLD)]),
            {"runtime": ["0.5", "0"], "base": False},
        )

    def test_moved_or_mismatched_tag_cannot_promote(self):
        self.assertEqual(
            POLICY.aliases("refs/tags/v0.5.4", OLD, NEW, [tag("v0.5.4", NEW)]),
            {"runtime": [], "base": False},
        )
        self.assertEqual(
            POLICY.aliases("refs/tags/v0.5.4", OLD, OLD, [tag("v0.5.4", NEW)]),
            {"runtime": [], "base": False},
        )

    def test_maintenance_line_does_not_roll_newer_major_or_base_back(self):
        tags = [tag("v0.4.9", OLD), tag("v0.5.4", NEW), tag("v1.0.0", NEW)]
        self.assertEqual(
            POLICY.aliases("refs/tags/v0.4.9", OLD, NEW, tags),
            {"runtime": ["0.4"], "base": False},
        )

    def test_feature_branch_does_not_promote_even_at_main_sha(self):
        self.assertEqual(
            POLICY.aliases("refs/heads/feature", NEW, NEW, []),
            {"runtime": [], "base": False},
        )

    def test_invalid_sha_fails_closed(self):
        with self.assertRaises(ValueError):
            POLICY.aliases("refs/heads/main", "bad", NEW, [])

    def test_tag_must_match_compiled_package_version(self):
        with self.assertRaises(ValueError):
            POLICY.validate_release("refs/tags/v0.5.4", "0.5.3")
        POLICY.validate_release("refs/tags/v0.5.4", "0.5.4")

    def test_unmerged_tag_source_fails_closed(self):
        for comparison in ("behind", "diverged"):
            with self.assertRaises(ValueError):
                POLICY.require_main_ancestry(OLD, NEW, comparison)
        POLICY.require_main_ancestry(OLD, NEW, "ahead")
        POLICY.require_main_ancestry(NEW, NEW, "identical")

    @mock.patch.dict(POLICY.os.environ, {"GH_TOKEN": FAKE_TOKEN})
    @mock.patch.object(POLICY.http.client, "HTTPSConnection")
    def test_github_api_uses_fixed_https_authority_and_all_tag_pages(self, connect):
        first_page = [tag(f"v0.1.{number}", OLD) for number in range(100)]
        last_page = [tag("v0.1.100", NEW)]
        responses = []
        for page in (first_page, last_page):
            response = mock.Mock(status=200)
            response.read.return_value = json.dumps(page).encode()
            responses.append(response)
        connection = connect.return_value
        connection.getresponse.side_effect = responses
        result = POLICY.api("repos/ThreatFlux/example/tags?per_page=100", pages=True)
        self.assertEqual(result, first_page + last_page)
        self.assertEqual(connect.call_count, 2)
        for call in connect.call_args_list:
            self.assertEqual(call.args, ("api.github.com",))
            self.assertEqual(call.kwargs["timeout"], 60)
            context = call.kwargs["context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, POLICY.ssl.CERT_REQUIRED)
        paths = [call.args[1] for call in connection.request.call_args_list]
        self.assertEqual(
            paths,
            [
                "/repos/ThreatFlux/example/tags?per_page=100&page=1",
                "/repos/ThreatFlux/example/tags?per_page=100&page=2",
            ],
        )
        for call in connection.request.call_args_list:
            self.assertEqual(call.args[0], "GET")
            self.assertEqual(
                call.kwargs["headers"]["Authorization"], "Bearer " + FAKE_TOKEN
            )
        self.assertEqual(connection.close.call_count, 2)

    @mock.patch.dict(POLICY.os.environ, {"GH_TOKEN": FAKE_TOKEN})
    @mock.patch.object(POLICY.http.client, "HTTPSConnection")
    def test_github_api_failure_refuses_alias_decision(self, connect):
        response = mock.Mock(status=403)
        connect.return_value.getresponse.return_value = response
        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            POLICY.api("repos/ThreatFlux/example/commits/main")
        response.read.assert_not_called()
        connect.return_value.close.assert_called_once()

    def test_fixed_scanner_package_version_is_read_from_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / "Cargo.toml"
            manifest.write_text(
                '[package]\nname = "threatflux-file-scanner"\nversion = "1.2.3"\n'
            )
            self.assertEqual(
                POLICY.selected_version(manifest, "threatflux-file-scanner"), "1.2.3"
            )
            with self.assertRaises(ValueError):
                POLICY.selected_version(manifest, "another-package")

    @mock.patch.dict(POLICY.os.environ, {"GITHUB_REF": "refs/heads/main"})
    @mock.patch.object(POLICY, "selected_version")
    @mock.patch.object(sys, "argv", ["container_publish_policy.py", "--validate"])
    def test_non_tag_build_does_not_require_a_root_package_version(self, version):
        POLICY.main()
        version.assert_not_called()


if __name__ == "__main__":
    unittest.main()
