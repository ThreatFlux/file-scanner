"""Receipt rules of scripts/binary_info_qualification.py that the hosted run relies on."""

import importlib.util
import json
import pathlib
import unittest

PATH = pathlib.Path(__file__).with_name("binary_info_qualification.py")
SPEC = importlib.util.spec_from_file_location("binary_info_qualification", PATH)
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)

SUPPORTED = {"available_sections": ["binary_info", "symbols"]}
UNSUPPORTED = {
    "available_sections": ["hashes"],
    "not_applicable": {"binary_info": "not an executable"},
}
RAW = {
    "format": "Raw",
    "architecture": "Unknown",
    "sections": {"count": 1, "sample": [".data"]},
    "imports": {"count": 0, "sample": []},
    "exports": {"count": 0, "sample": []},
}


def page(*items):
    return {"items": list(items), "total": len(items)}


def pe_pages(imports=()):
    return {
        "sections": page({"name": ".text"}),
        "imports": page(*imports),
        "exports": page("fixture_export"),
    }


PE_INFO = {"format": "PE", "architecture": "x86_64", "entry_point": 5368713216}
PE_ENTRIES = (4096, 5368713216)


class Receipt(unittest.TestCase):
    def test_analyze_result_and_sections_page_have_distinct_request_ids(self):
        messages, ids = Q.plan({Q.PE: pathlib.Path("/q/samples/pe_fixture.exe")})
        calls = {
            message["id"]: message["params"]["name"]
            for message in messages
            if message["method"] == "tools/call"
        }
        self.assertEqual(set(ids.values()), set(calls))
        self.assertEqual(calls[ids[(Q.PE, "analysis")]], "analyze_file")
        self.assertEqual(calls[ids[(Q.PE, "page", "sections")]], "query_analysis")

    def test_text_control_must_be_unsupported_everywhere(self):
        record, checks = Q.text_record(UNSUPPORTED, RAW)
        self.assertTrue(all(checks.values()))
        self.assertEqual(record["verdict"], "unsupported")
        self.assertEqual(record["entry_point"], {"status": "unsupported"})
        contradictions = [
            (SUPPORTED, RAW),
            (dict(UNSUPPORTED, available_sections=["binary_info"]), RAW),
            (UNSUPPORTED, dict(RAW, format="ELF")),
            (UNSUPPORTED, dict(RAW, entry_point=4096)),
            (UNSUPPORTED, dict(RAW, compiler="GCC/GNU")),
            (UNSUPPORTED, dict(RAW, exports={"count": 1, "sample": ["x"]})),
        ]
        for overview, info in contradictions:
            record, checks = Q.text_record(overview, info)
            self.assertEqual(record, {"verdict": "contradictory"})
            self.assertFalse(all(checks.values()))

    def test_absent_compiler_and_linker_are_optional(self):
        record, checks = Q.binary_record(
            Q.PE, SUPPORTED, PE_INFO, pe_pages(), PE_ENTRIES
        )
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(record["compiler"], {"status": "absent"})
        self.assertEqual(record["linker"], {"status": "absent"})
        self.assertEqual(
            record["imports"], {"status": "empty", "count": 0, "required": {}}
        )
        failed = Q.binary_record(
            Q.PE,
            SUPPORTED,
            PE_INFO,
            pe_pages(["ExitProcess (KERNEL32.dll)"]),
            PE_ENTRIES,
        )[1]
        self.assertEqual(
            [k for k, ok in failed.items() if not ok], [f"{Q.PE}.imports.empty"]
        )

    def test_only_allowlisted_values_are_exported(self):
        info = dict(
            PE_INFO,
            compiler="/home/someone/cc",
            linker="Linker v14.0",
            architecture={"x": 1},
            entry_point="0x1000",
        )
        record, checks = Q.binary_record(Q.PE, SUPPORTED, info, pe_pages(), PE_ENTRIES)
        self.assertEqual(
            record["compiler"], {"status": "reported", "value_withheld": True}
        )
        self.assertEqual(
            record["linker"], {"status": "reported", "value": "Linker v14.0"}
        )
        self.assertEqual(
            record["entry_point"], {"status": "reported", "value_withheld": True}
        )
        self.assertNotIn("someone", json.dumps(record))
        self.assertFalse(
            checks[f"{Q.PE}.architecture"] or checks[f"{Q.PE}.entry_point"]
        )

    def test_entry_point_matches_the_binary_header(self):
        for entry in (*PE_ENTRIES, 4095, True):
            info = dict(PE_INFO, entry_point=entry)
            checks = Q.binary_record(Q.PE, SUPPORTED, info, pe_pages(), PE_ENTRIES)[1]
            self.assertEqual(checks[f"{Q.PE}.entry_point"], entry in PE_ENTRIES)

    def test_answers_must_describe_the_fixture(self):
        path, data = pathlib.Path("/q/samples/pe_fixture.exe"), b"MZ"
        digest = Q.hashlib.sha256(data).hexdigest()
        overview = {"file_path": str(path), "size": 2, "sha256": digest}
        sections = {
            "file_path": str(path),
            "sha256": digest,
            "hashes": {"sha256": digest},
            "binary_info": {},
            "signatures": {},
        }
        pages = {
            "exports": {
                "file_path": str(path),
                "section": "binary_info",
                "list": "exports",
                "offset": 0,
                "returned": 0,
                "unfiltered_total": 0,
                "total": 0,
                "items": [],
            }
        }
        self.assertEqual(
            Q.verify_identity(Q.PE, path, data, overview, sections, pages), digest
        )
        broken = [
            (dict(overview, sha256="0" * 64), sections, pages),
            (dict(overview, size=3), sections, pages),
            (overview, dict(sections, hashes={"sha256": "0" * 64}), pages),
            (overview, dict(sections, file_path="/q/other"), pages),
            (overview, sections, {"exports": dict(pages["exports"], next_offset=500)}),
            (overview, sections, {"exports": dict(pages["exports"], list="imports")}),
            (
                overview,
                sections,
                {"exports": dict(pages["exports"], items=["unexpected"])},
            ),
            (overview, sections, {"exports": dict(pages["exports"], returned=1)}),
            (overview, {k: v for k, v in sections.items() if k != "signatures"}, pages),
        ]
        for o, s, p in broken:
            with self.assertRaises(Q.Refused) as refused:
                Q.verify_identity(Q.PE, path, data, o, s, p)
            self.assertNotIn("/q/", str(refused.exception))

    def test_tool_errors_are_not_quoted(self):
        by_id = {
            7: {
                "result": {
                    "isError": True,
                    "content": [{"text": "cannot read /home/someone/x"}],
                }
            }
        }
        for key, name in (
            ((Q.ELF, "analysis"), "analysis"),
            ((Q.ELF, "page", "sections"), "sections"),
        ):
            with self.subTest(key=key):
                with self.assertRaises(Q.Refused) as refused:
                    Q.answer(by_id, {key: 7}, key)
                self.assertEqual(
                    str(refused.exception), f"{Q.ELF}: the {name} call failed"
                )


if __name__ == "__main__":
    unittest.main()
