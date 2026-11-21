#!/usr/bin/env python3
"""Qualify the binary_info metadata of a file-scanner build on three known files.

Builds two benign fixtures from tests/fixtures/binary_info_qualification (an
x86_64 ELF linked against glibc by clang's default linker, and a freestanding
x86_64 PE linked by the ld.lld passed to clang with --ld-path, no imports),
copies the plain-text control, and asks one `file-scanner mcp-stdio` server
(the transport of scripts/mcp-smoke.py) about each file: the analyze_file
overview, analyze_file with binary_info, hashes and signatures, and for the two
binaries query_analysis on the sections, imports and exports lists. Nothing
but clang, ld.lld, git and the scanner is run; the fixtures are only read.

An answer is used only after its path, size and SHA-256 match the fixture. The
receipt holds allowlisted values only (hashes, counts, known format and
compiler names, validated versions); tool error text, paths and unknown keys
are never copied, and diagnostics name a stage, not a path.

Usage: python3 scripts/binary_info_qualification.py target/release/file-scanner [--receipt PATH]
Exit status: 0 qualified, 1 a check failed, 2 qualification could not run.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import queue
import re
import shutil
import struct

# Fixed argument vectors, no shell, bounded waits (see run()).
import subprocess  # nosec B404
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "binary_info_qualification"
SCHEMA = "file-scanner.binary-info-qualification/v1"
TIMEOUT = 120
ELF, PE, TEXT = "elf-x86_64-clang", "pe-x86_64-clang-lld", "text-control"
FILES = {ELF: "elf_fixture", PE: "pe_fixture.exe", TEXT: "text_control.txt"}
LISTS = ("sections", "imports", "exports")
FIELDS = ("format", "architecture", "entry_point", "compiler", "linker") + LISTS
# What each binary must show; a name may appear as `name (library)`.
EXPECT = {
    ELF: {
        "format": "ELF",
        "architecture": "x86_64",
        "required": {
            "sections": [".text"],
            "imports": ["puts"],
            "exports": ["fixture_export"],
        },
    },
    PE: {
        "format": "PE",
        "architecture": "x86_64",
        "empty": ["imports"],
        "required": {"sections": [".text"], "exports": ["fixture_export"]},
    },
}
# The only tool strings a receipt may carry (src/binary_parser.rs vocabulary).
FORMATS = {"ELF", "PE", "Mach-O", "Java", "WebAssembly", "Raw", "Unknown"}
ARCHITECTURES = {"x86", "x86_64", "ARM", "ARM64", "Unknown"}
COMPILERS = {
    "GCC/GNU",
    "Clang",
    "MinGW/GCC",
    "Apple Clang",
    "MSVC 2015-2022",
    "MSVC 2013",
    "MSVC 2012",
    "MSVC 2010",
    "MSVC 2008",
    "MSVC 2005",
    "MSVC 2003",
    "MSVC 6.0",
}
LINKER = re.compile(r"^(Linker v\d{1,3}\.\d{1,3}|Apple LD)$")
SEMVER = re.compile(r"[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}(-[0-9A-Za-z.]{1,32})?")
HEX40 = re.compile(r"[0-9a-f]{40}")

sys.dont_write_bytecode = True
_SPEC = importlib.util.spec_from_file_location(
    "mcp_smoke", pathlib.Path(__file__).with_name("mcp-smoke.py")
)
SMOKE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(SMOKE)


class Refused(Exception):
    """The qualification stopped; the message is a fixed, path-free stage name."""


def sha256_file(path):
    with pathlib.Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run(argv, cwd=None):
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,  # nosec B603
            timeout=TIMEOUT,
            shell=False,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def version_of(executable, pattern):
    done = run([executable, "--version"])
    found = re.search(pattern, done.stdout) if done and done.returncode == 0 else None
    if not found:
        raise Refused(f"no version from {pathlib.Path(executable).name}")
    return found.group(1)


# ---------------------------------------------------------------------------
# Reading answers (pure; scripts/test_binary_info_qualification.py)
# ---------------------------------------------------------------------------


def scalar(info, key, allowed):
    """`absent`, or `reported` with the value when it is in the allowlist."""
    value = info.get(key)
    if value is None:
        return {"status": "absent"}
    if isinstance(allowed, re.Pattern):
        safe = isinstance(value, str) and allowed.fullmatch(value) is not None
    else:
        safe = isinstance(value, str) and value in allowed
    return (
        {"status": "reported", "value": value}
        if safe
        else {"status": "reported", "value_withheld": True}
    )


def listed(page, required):
    names = [i.get("name") if isinstance(i, dict) else i for i in page["items"]]
    names = [n for n in names if isinstance(n, str)]
    return {
        "status": "reported" if page["total"] else "empty",
        "count": page["total"],
        "required": {
            w: any(n == w or n.startswith(w + " (") for n in names) for w in required
        },
    }


def overview_verdict(overview):
    available = "binary_info" in (overview.get("available_sections") or [])
    not_applicable = "binary_info" in (overview.get("not_applicable") or {})
    if available and not not_applicable:
        return "supported"
    if not_applicable and not available:
        return "unsupported"
    return "contradictory"


def header_entry_points(label, data):
    """Read the entry point from an x86_64 fixture's own header."""
    try:
        if label == ELF and data.startswith(b"\x7fELF\x02\x01"):
            (entry,) = struct.unpack_from("<Q", data, 24)
            return (entry,) if entry else ()
        if label == PE and data.startswith(b"MZ"):
            (pe,) = struct.unpack_from("<I", data, 60)
            optional = pe + 24
            if (
                data[pe : pe + 4] == b"PE\0\0"
                and data[optional : optional + 2] == b"\x0b\x02"
            ):
                (entry,) = struct.unpack_from("<I", data, optional + 16)
                (base,) = struct.unpack_from("<Q", data, optional + 24)
                # The SDK reports the virtual address. The native fallback reports the RVA.
                return (entry, base + entry) if entry else ()
    except struct.error:
        return ()
    return ()


def binary_record(label, overview, info, pages, expected_entries):
    """(binary_info record, checks) of a fixture that must be supported."""
    expect = EXPECT[label]
    rec = {"verdict": overview_verdict(overview)}
    rec["format"] = scalar(info, "format", FORMATS)
    rec["architecture"] = scalar(info, "architecture", ARCHITECTURES)
    entry = info.get("entry_point")
    valid_entry = type(entry) is int and 0 < entry < 2**64
    if entry is None:
        rec["entry_point"] = {"status": "absent"}
    else:
        rec["entry_point"] = {
            "status": "reported",
            **({"value": entry} if valid_entry else {"value_withheld": True}),
        }
    # Optional heuristics of the tool (section names, PE linker version): reported, never checked.
    rec["compiler"] = scalar(info, "compiler", COMPILERS)
    rec["linker"] = scalar(info, "linker", LINKER)
    for name in LISTS:
        rec[name] = listed(pages[name], expect["required"].get(name, []))
    checks = {
        f"{label}.overview_supported": rec["verdict"] == "supported",
        f"{label}.format": rec["format"].get("value") == expect["format"],
        f"{label}.architecture": rec["architecture"].get("value")
        == expect["architecture"],
        f"{label}.entry_point": valid_entry and entry in expected_entries,
    }
    for name in LISTS:
        for wanted, present in rec[name]["required"].items():
            checks[f"{label}.{name}.{wanted}"] = present
    for name in expect.get("empty", []):
        checks[f"{label}.{name}.empty"] = rec[name]["status"] == "empty"
    return rec, checks


def count_of(info, key):
    value = info.get(key)
    return value.get("count") if isinstance(value, dict) else None


def text_record(overview, info):
    """(binary_info record, checks) of the control: unsupported, with nothing executable-looking."""
    checks = {
        f"{TEXT}.overview_unsupported": overview_verdict(overview) == "unsupported",
        f"{TEXT}.section_format_raw": info.get("format") == "Raw",
        f"{TEXT}.no_architecture": info.get("architecture") in (None, "Unknown"),
        f"{TEXT}.no_entry_point": info.get("entry_point") is None,
        f"{TEXT}.no_compiler_or_linker": info.get("compiler") is None
        and info.get("linker") is None,
        f"{TEXT}.no_imports_or_exports": count_of(info, "imports") == 0
        and count_of(info, "exports") == 0,
    }
    if not all(checks.values()):
        return {"verdict": "contradictory"}, checks
    return dict(
        {"verdict": "unsupported"}, **{f: {"status": "unsupported"} for f in FIELDS}
    ), checks


def signature_record(label, signatures):
    unsigned = signatures.get("is_signed") is False
    none_found = signatures.get("verification_status") == "No signature found"
    rec = {
        "is_signed": signatures.get("is_signed")
        if isinstance(signatures.get("is_signed"), bool)
        else None,
        "status": "none_found" if none_found else "other",
    }
    return rec, {f"{label}.unsigned": unsigned and none_found}


def full_fixture_page(page, path, name):
    items = page.get("items")
    if not isinstance(items, list) or type(page.get("total")) is not int:
        return False
    expected = {
        "file_path": str(path),
        "section": "binary_info",
        "list": name,
        "offset": 0,
        "total": len(items),
        "unfiltered_total": len(items),
        "returned": len(items),
    }
    return "next_offset" not in page and all(
        page.get(key) == value for key, value in expected.items()
    )


def verify_identity(label, path, data, overview, sections, pages):
    """Refuse answers that do not describe this exact fixture."""
    digest = hashlib.sha256(data).hexdigest()
    hashes = sections.get("hashes") or {}
    same = (
        overview.get("file_path") == str(path)
        and overview.get("size") == len(data)
        and overview.get("sha256") == digest
        and sections.get("file_path") == str(path)
        and sections.get("sha256") == digest
        and hashes.get("sha256") == digest
    )
    if not same:
        raise Refused(
            f"{label}: an answer does not match the fixture path, size or SHA-256"
        )
    if not all(full_fixture_page(page, path, name) for name, page in pages.items()):
        raise Refused(f"{label}: a binary_info list is incomplete or misattributed")
    for name in ("binary_info", "signatures"):
        if not isinstance(sections.get(name), dict):
            raise Refused(f"{label}: the {name} section produced no result")
    return digest


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def build(clang, lld, work):
    """Compile the binaries in `work` (relative names keep it out of the images)."""
    for name in ("elf_fixture.c", "pe_fixture.c", "text_control.txt"):
        shutil.copyfile(FIXTURES / name, work / name)
    commands = {
        ELF: [clang, "-O1", "-rdynamic", "-o", FILES[ELF], "elf_fixture.c"],
        PE: [
            clang,
            "--target=x86_64-w64-windows-gnu",
            "-fuse-ld=lld",
            f"--ld-path={lld}",
            "-O1",
            "-ffreestanding",
            "-fno-stack-protector",
            "-nostdlib",
            "-Wl,--entry=fixture_start",
            "-Wl,--subsystem,console",
            "-Wl,--no-insert-timestamp",
            "-o",
            FILES[PE],
            "pe_fixture.c",
        ],
    }
    for label, argv in commands.items():
        done = run(argv, cwd=work)
        if done is None or done.returncode != 0 or not (work / FILES[label]).is_file():
            raise Refused(f"compiling the {label} fixture failed")
    magic = {ELF: b"\x7fELF", PE: b"MZ"}
    for label, head in magic.items():
        if (work / FILES[label]).read_bytes()[: len(head)] != head:
            raise Refused(f"the {label} fixture has the wrong magic")
    return {label: work / name for label, name in FILES.items()}


def plan(paths):
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": SMOKE.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "file-scanner-qualification",
                    "version": "1.0.0",
                },
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    ids = {}

    def call(key, name, arguments):
        ids[key] = len(messages)
        messages.append(
            {
                "jsonrpc": "2.0",
                "id": ids[key],
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    for label, path in paths.items():
        call((label, "overview"), "analyze_file", {"file_path": str(path)})
        call(
            (label, "analysis"),
            "analyze_file",
            {
                "file_path": str(path),
                "sections": ["binary_info", "hashes", "signatures"],
                "max_output_bytes": 400_000,
            },
        )
        if label != TEXT:
            for name in LISTS:
                call(
                    (label, "page", name),
                    "query_analysis",
                    {
                        "file_path": str(path),
                        "section": "binary_info",
                        "list": name,
                        "limit": 500,
                        "detail": True,
                        "max_output_bytes": 400_000,
                    },
                )
    return messages, ids


def answer(by_id, ids, key):
    response = by_id.get(ids[key]) or {}
    result = response.get("result")
    try:
        if "error" in response or not isinstance(result, dict) or result.get("isError"):
            raise TypeError
        value = json.loads(result["content"][0]["text"])
        if not isinstance(value, dict):
            raise TypeError
        return value
    except (ValueError, KeyError, IndexError, TypeError):
        raise Refused(f"{key[0]}: the {key[-1]} call failed") from None


def source_facts():
    done = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    revision = (
        done.stdout.strip()
        if done and done.returncode == 0
        else os.environ.get("GITHUB_SHA", "")
    )
    lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8").replace("\r\n", "\n")
    sdk = re.search(
        r'^name = "threatflux-binary-analysis"\nversion = "([^"\n]+)"',
        lock,
        re.MULTILINE,
    )
    if not HEX40.fullmatch(revision) or not sdk or not SEMVER.fullmatch(sdk.group(1)):
        raise Refused("the source revision or the resolved SDK version is unknown")
    # Tracked changes only (the build writes untracked files); None when git cannot say.
    status = run(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"]
    )
    clean = (status.stdout.strip() == "") if status and status.returncode == 0 else None
    return revision, clean, sdk.group(1)


def fixture_tools():
    clang, lld = shutil.which("clang"), shutil.which("ld.lld")
    if not clang or not lld:
        raise Refused("clang and ld.lld are required")
    # which() gives an absolute path; symlinks are kept so ld.lld keeps its name.
    lld = os.path.abspath(lld)
    return (
        clang,
        lld,
        {
            "clang": version_of(clang, r"clang version (\d+\.\d+\.\d+)"),
            "pe_linker": {
                "name": "ld.lld",
                "passed_as": "--ld-path",
                "sha256": sha256_file(lld),
                "version": version_of(lld, r"LLD (\d+\.\d+\.\d+)"),
            },
            "elf_linker": "clang default, not verified",
        },
    )


def scan_fixtures(binary, work, cache, messages):
    scanner_sha = sha256_file(binary)
    try:
        by_id = SMOKE.run_session(binary, work, cache, messages)
    except (OSError, RuntimeError, ValueError, queue.Empty, subprocess.SubprocessError):
        raise Refused("the MCP session failed") from None
    if sha256_file(binary) != scanner_sha:
        raise Refused("the scanner executable changed during the run")
    server = (by_id.get(1) or {}).get("result") or {}
    info = server.get("serverInfo") or {}
    if (
        info.get("name") != "file-scanner"
        or not SEMVER.fullmatch(str(info.get("version", "")))
        or server.get("protocolVersion") != SMOKE.PROTOCOL_VERSION
    ):
        raise Refused("initialize did not name a file-scanner server")
    return by_id, {
        "sha256": scanner_sha,
        "version": info["version"],
        "protocol_version": SMOKE.PROTOCOL_VERSION,
    }


def fixture_records(paths, by_id, ids):
    fixtures, checks = {}, {}
    for label, path in paths.items():
        data = path.read_bytes()
        overview = answer(by_id, ids, (label, "overview"))
        sections = answer(by_id, ids, (label, "analysis"))
        pages = (
            {name: answer(by_id, ids, (label, "page", name)) for name in LISTS}
            if label != TEXT
            else {}
        )
        digest = verify_identity(label, path, data, overview, sections, pages)
        if label == TEXT:
            record, found = text_record(overview, sections["binary_info"])
        else:
            record, found = binary_record(
                label,
                overview,
                sections["binary_info"],
                pages,
                header_entry_points(label, data),
            )
        signature, signed = signature_record(label, sections["signatures"])
        checks.update(found)
        checks.update(signed)
        fixtures[label] = {
            "sha256": digest,
            "size": len(data),
            "binary_info": record,
            "signature": signature,
        }
    return fixtures, dict(sorted(checks.items()))


def qualify(binary, revision, clean, sdk_version):
    clang, lld, toolchain = fixture_tools()
    with tempfile.TemporaryDirectory(prefix="file-scanner-qualify-") as directory:
        base = pathlib.Path(directory).resolve()
        work, cache = base / "samples", base / "cache"
        work.mkdir()
        cache.mkdir()
        paths = build(clang, lld, work)
        if sha256_file(lld) != toolchain["pe_linker"]["sha256"]:
            raise Refused("the PE linker changed during fixture compilation")
        messages, ids = plan(paths)
        by_id, scanner = scan_fixtures(binary, work, cache, messages)
        fixtures, checks = fixture_records(paths, by_id, ids)
    return {
        "schema": SCHEMA,
        "outcome": "qualified" if all(checks.values()) else "failed",
        "source_revision": revision,
        "source_tree_clean": clean,
        "scanner": scanner,
        "route": {
            "transport": "mcp-stdio",
            "tools": ["analyze_file", "query_analysis"],
        },
        "parser": {
            "sdk": "threatflux-binary-analysis",
            "sdk_version": sdk_version,
            "per_result_origin": "not_exposed",
        },
        "toolchain": toolchain,
        "fixtures": fixtures,
        "checks": checks,
    }


def write_receipt(receipt, path):
    body = json.dumps(receipt, indent=2) + "\n"
    if path is None:
        sys.stdout.write(body)
        return
    target = pathlib.Path(path)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent, delete=False
        ) as output:
            temp_path = pathlib.Path(output.name)
            output.write(body)
        os.replace(temp_path, target)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary")
    parser.add_argument("--receipt", help="write the receipt here (default: stdout)")
    args = parser.parse_args(argv)
    try:
        binary = pathlib.Path(args.binary).resolve()
        if binary.name != "file-scanner" or not binary.is_file():
            raise Refused("pass a local file-scanner build")
        receipt = qualify(binary, *source_facts())
    except Refused as error:
        receipt = {"schema": SCHEMA, "outcome": "error", "stage": str(error)}
    except (OSError, AttributeError, KeyError, TypeError, ValueError):
        receipt = {
            "schema": SCHEMA,
            "outcome": "error",
            "stage": "read inputs or responses",
        }
    try:
        write_receipt(receipt, args.receipt)
    except OSError:
        print("error: the qualification receipt could not be written", file=sys.stderr)
        return 2
    if receipt["outcome"] == "error":
        print(f"error: {receipt['stage']}", file=sys.stderr)
        return 2
    failed = [name for name, ok in receipt["checks"].items() if not ok]
    print(
        f"binary_info qualification {receipt['outcome']}: {len(receipt['checks'])} checks"
        + (f", failed: {', '.join(failed)}" if failed else ""),
        file=sys.stderr,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
