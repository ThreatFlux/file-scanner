"""Release stamping regressions for the server.json template."""

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import tempfile
import unittest

PATH = pathlib.Path(__file__).parent / "stamp_server_json.py"
sys.path.insert(0, str(PATH.parent))
SPEC = importlib.util.spec_from_file_location("stamp_server_json", PATH)
STAMP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAMP)
ROOT = PATH.parent.parent
TEMPLATE = (ROOT / "server.json").read_text(encoding="utf-8")


def mutated(change):
    data = json.loads(TEMPLATE)
    change(data)
    return STAMP.render(data)


def run_cli(*args):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        try:
            code = STAMP.main(list(args))
        except SystemExit as exit_error:
            code = exit_error.code
    return code, err.getvalue()


class StampServerJson(unittest.TestCase):
    def test_committed_template_and_dockerfile_hold_placeholder(self):
        self.assertEqual(run_cli("--check")[0], 0)
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(docker.count("ARG VERSION=0.0.0\n"), 2)
        self.assertEqual(TEMPLATE.count('"0.0.0"'), 2)
        self.assertEqual(TEMPLATE.count("file-scanner:0.0.0"), 1)

    def test_stamp_changes_exactly_three_strings(self):
        for version in ("0.4.3", "1.2.3-rc.1", "10.20.30-beta.2.x"):
            out = STAMP.stamp(TEMPLATE, version)
            old, new = TEMPLATE.splitlines(), out.splitlines()
            self.assertEqual(len(old), len(new))
            changed = [(a, b) for a, b in zip(old, new) if a != b]
            self.assertEqual(len(changed), 3)
            self.assertEqual(out.count(version), 3)
            self.assertEqual(out.replace(version, "0.0.0"), TEMPLATE)
            data = json.loads(out)
            self.assertEqual(data["version"], version)
            self.assertEqual(data["packages"][0]["version"], version)
            self.assertEqual(data["packages"][1]["identifier"], f"ghcr.io/threatflux/file-scanner:{version}")

    def test_formatting_is_stable(self):
        out = STAMP.stamp(TEMPLATE, "0.0.0")
        self.assertEqual(out, TEMPLATE)
        self.assertTrue(TEMPLATE.endswith("}\n"))
        self.assertFalse(TEMPLATE.endswith("\n\n"))
        self.assertIn('{host_dir}:{host_dir}:ro', TEMPLATE)

    def test_bad_versions_are_refused(self):
        bad = ["", "1.2", "v1.2.3", "1.2.3-", "1.2.3+build", "1.2.3 ", "1.2.3\n", "1.2.3-a_b", "a.b.c", "1.2.3-rc.1\n"]
        for version in bad:
            with self.assertRaises(STAMP.StampError, msg=repr(version)):
                STAMP.stamp(TEMPLATE, version)

    def test_bad_templates_are_refused(self):
        def drop_oci(d):
            d["packages"].pop()

        def dup_cargo(d):
            d["packages"].append(dict(d["packages"][0]))

        def rename_cargo(d):
            d["packages"][0]["identifier"] = "other"

        def other_image(d):
            d["packages"][1]["identifier"] = "ghcr.io/other/image:0.0.0"

        def untagged_image(d):
            d["packages"][1]["identifier"] = "ghcr.io/threatflux/file-scanner"

        def stale_top(d):
            d["version"] = "0.4.0"

        def stale_cargo(d):
            d["packages"][0]["version"] = "0.4.0"

        def stale_oci(d):
            d["packages"][1]["identifier"] = "ghcr.io/threatflux/file-scanner:0.4.0"

        def no_version(d):
            del d["version"]

        def bare_oci(d):
            d["packages"][1]["identifier"] = "0.0.0"

        def extra_package(d):
            d["packages"].append({"registryType": "npm", "identifier": "x", "version": "0.0.0"})

        for change in (drop_oci, dup_cargo, rename_cargo, other_image, untagged_image, bare_oci,
                       stale_top, stale_cargo, stale_oci, no_version, extra_package):
            with self.assertRaises(STAMP.StampError, msg=change.__name__):
                STAMP.stamp(mutated(change), "0.4.3")
        for text in ("[]", '{"packages": 3}'):
            with self.assertRaises(STAMP.StampError):
                STAMP.stamp(text, "0.4.3")

    def test_formatting_drift_is_refused(self):
        with self.assertRaises(STAMP.StampError):
            STAMP.stamp(TEMPLATE.rstrip("\n"), "0.4.3")
        with self.assertRaises(STAMP.StampError):
            STAMP.stamp(json.dumps(json.loads(TEMPLATE), indent=4) + "\n", "0.4.3")

    def test_cli_writes_nothing_on_refusal_and_stamps_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "nested" / "server.json"
            code, err = run_cli("--version", "v1.2.3", "--output", str(out))
            self.assertEqual(code, 1)
            self.assertIn("invalid version", err)
            self.assertFalse(out.exists())
            self.assertFalse(out.parent.exists())
            bad = pathlib.Path(tmp) / "bad.json"
            bad.write_text(TEMPLATE.replace('"0.0.0"', '"0.4.0"', 1), encoding="utf-8")
            code, _ = run_cli("--template", str(bad), "--version", "0.4.3", "--output", str(out))
            self.assertEqual(code, 1)
            self.assertFalse(out.exists())
            self.assertFalse(out.parent.exists())
            code, _ = run_cli("--template", str(bad), "--check")
            self.assertEqual(code, 1)
            self.assertEqual(run_cli("--version", "0.4.3")[0], 2)
            self.assertEqual(run_cli("--version", "0.4.3", "--output", str(out))[0], 0)
            self.assertEqual(out.read_text(encoding="utf-8"), STAMP.stamp(TEMPLATE, "0.4.3"))

    def test_dockerfile_check_rejects_real_versions(self):
        good = "ARG VERSION=0.0.0\nARG VERSION=0.0.0\n"
        STAMP.check_dockerfile(good)
        multi = "ARG BUILD_DATE=x VERSION=0.4.2\nARG VERSION=0.0.0\nARG VERSION=0.0.0\n"
        commented = "# ARG VERSION=0.0.0\nARG VERSION=0.0.0\nARG VERSION=0.4.2\n"
        suffixed = "ARG VERSION=0.0.0\nARG VERSION=0.0.0-dev\n"
        for text in ("ARG VERSION=0.4.0\nARG VERSION=0.0.0\n", "ARG VERSION=0.0.0\n", good + good, multi,
                     commented, suffixed):
            with self.assertRaises(STAMP.StampError):
                STAMP.check_dockerfile(text)

    def test_version_pattern_matches_release_workflow(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        found = re.findall(r'\[\[ "\$\{VERSION\}" =~ (\^\[0-9\].*\$) \]\]', workflow)
        self.assertEqual(found, [STAMP.VERSION_RE.pattern])
        for version in ("1.0.0-RC.1", "01.02.03", "1.2.3-.", "1.2.3-a..b"):
            self.assertIn('"' + version + '"', STAMP.stamp(TEMPLATE, version))

    def test_refusals_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            out = tmp / "out.json"
            code, err = run_cli("--template", str(tmp / "missing.json"), "--check")
            self.assertEqual((code, err.startswith("error:")), (1, True))
            (tmp / "bad.json").write_text("{", encoding="utf-8")
            code, err = run_cli("--template", str(tmp / "bad.json"), "--check")
            self.assertEqual((code, err.startswith("error:")), (1, True))
            (tmp / "odd.json").write_text(STAMP.render({"packages": ["x"]}), encoding="utf-8")
            code, err = run_cli("--template", str(tmp / "odd.json"), "--version", "1.0.0", "--output", str(out))
            self.assertEqual((code, err.startswith("error:"), out.exists()), (1, True, False))
            crlf = tmp / "crlf.json"
            crlf.write_bytes(TEMPLATE.replace("\n", "\r\n").encode("utf-8"))
            self.assertEqual(run_cli("--template", str(crlf), "--check")[0], 1)
            same = tmp / "same.json"
            same.write_text(TEMPLATE, encoding="utf-8")
            code, _ = run_cli("--template", str(same), "--version", "1.0.0", "--output", str(same))
            self.assertEqual(code, 1)
            self.assertEqual(same.read_text(encoding="utf-8"), TEMPLATE)
            (tmp / "int.json").write_text(STAMP.render({"packages": [
                {"registryType": "cargo", "identifier": STAMP.CARGO_NAME, "version": "0.0.0"},
                {"registryType": "oci", "identifier": 5}], "version": "0.0.0"}), encoding="utf-8")
            code, err = run_cli("--template", str(tmp / "int.json"), "--check")
            self.assertEqual((code, err.startswith("error:")), (1, True))
            docker = tmp / "Dockerfile"
            docker.write_text("ARG VERSION=0.4.0\nARG VERSION=0.0.0\n", encoding="utf-8")
            self.assertEqual(run_cli("--check", "--dockerfile", str(docker))[0], 1)

    def test_dockerfile_check_rejects_indented_and_lowercase(self):
        good = "ARG VERSION=0.0.0\nARG VERSION=0.0.0\n"
        for extra in ("  ARG VERSION=0.4.0\n", "arg VERSION=0.4.0\n"):
            with self.assertRaises(STAMP.StampError):
                STAMP.check_dockerfile(good + extra)

    def test_non_ascii_is_not_escaped(self):
        text = mutated(lambda d: d.update(title="Fil\u00e9 Scanner"))
        data = json.loads(text)
        self.assertIn("\u00e9", STAMP.render(data))

    def test_cli_keeps_utf8_and_refuses_bom(self):
        text = mutated(lambda d: d.update(title="Fil\u00e9 Scanner"))
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            src, out = tmp / "server.json", tmp / "out.json"
            src.write_bytes(text.encode("utf-8"))
            self.assertEqual(run_cli("--template", str(src), "--version", "1.2.3", "--output", str(out))[0], 0)
            self.assertEqual(out.read_bytes(), STAMP.stamp(text, "1.2.3").encode("utf-8"))
            out.unlink()
            src.write_bytes(b"\xef\xbb\xbf" + TEMPLATE.encode("utf-8"))
            code, err = run_cli("--template", str(src), "--version", "1.2.3", "--output", str(out))
            self.assertEqual((code, err.startswith("error:"), out.exists()), (1, True, False))


if __name__ == "__main__":
    unittest.main()
