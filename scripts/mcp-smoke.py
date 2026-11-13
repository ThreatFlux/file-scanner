#!/usr/bin/env python3
"""Run a bounded MCP handshake against a caller-selected file-scanner build.

The script starts `file-scanner mcp-stdio` once and sends, in order: initialize,
notifications/initialized, tools/list, an analyze_file overview call, an analyze_file
call for the strings section and a query_analysis drill-down on the same file. It then checks that

* the server answered every request and answered nothing else (a notification
  gets no reply),
* every line on stdout is a JSON-RPC 2.0 message (diagnostics belong on stderr),
* tools/list names exactly the 17 expected tools,
* the overview describes the right file, and
* the drill-down was served from the cache (`"cache": "hit"`).

Usage: python3 scripts/mcp-smoke.py target/release/file-scanner
"""

import hashlib
import json
import os
from pathlib import Path
# This smoke test intentionally executes the local scanner with a fixed argument vector.
import subprocess  # nosec B404
import sys
import queue
import tempfile
import threading

# Newest revision that an initialize request negotiates on stdio (older ones work too).
PROTOCOL_VERSION = "2025-11-25"

EXPECTED_TOOLS = {
    "analyze_document",
    "analyze_file",
    "analyze_java_file",
    "analyze_npm_package",
    "analyze_python_package",
    "analyze_script",
    "cache_clear",
    "cache_status",
    "compare_files",
    "disassemble",
    "inspect_archive",
    "llm_analyze_file",
    "query_analysis",
    "read_hex",
    "search_strings",
    "string_details",
    "yara_scan_file",
}

REQUEST_TIMEOUT = 60
SAMPLE_URL = "http://smoke.example.test/path"


def requests_for(fixture):
    return [
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "file-scanner-ci", "version": "1.0.0"},
            },
        },
        # The handshake is complete only after this notification; a server must not answer it.
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "analyze_file", "arguments": {"file_path": str(fixture)}},
        },
        {
            # Summarizes the strings section and caches the full list.
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "analyze_file",
                "arguments": {"file_path": str(fixture), "sections": ["strings"]},
            },
        },
        {
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {
                "name": "query_analysis",
                "arguments": {"file_path": str(fixture), "section": "strings", "filter": "smoke"},
            },
        },
    ]


def parse_line(line):
    try:
        message = json.loads(line)
    except ValueError as error:
        raise RuntimeError(f"stdout carries a line that is not JSON: {line[:200]!r}") from error
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise RuntimeError(f"stdout carries a line that is not JSON-RPC 2.0: {line[:200]!r}")
    return message


def exchange(binary, fixture, cache_dir):
    binary = Path(binary).resolve(strict=True)
    if binary.name != "file-scanner" or not binary.is_file():
        raise ValueError("Pass a local file-scanner build artifact")
    env = dict(os.environ, FILE_SCANNER_CACHE_DIR=str(cache_dir))
    # The caller chooses its local build directory; executable/arguments are fixed
    # apart from the temporary directories made by this script, shell expansion is
    # disabled, and every wait is bounded. No remote input is used.
    server = subprocess.Popen(  # nosec B603
        ["./file-scanner", "mcp-stdio", "--allow-root", str(fixture.parent)], cwd=binary.parent,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, shell=False, env=env,
    )
    lines = queue.Queue()

    def pump():
        for line in server.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    by_id = {}
    try:
        # A client waits for each answer before it sends the next request, so the
        # cache is warm when the drill-down arrives.
        for message in requests_for(fixture):
            server.stdin.write(json.dumps(message) + "\n")
            server.stdin.flush()
            if "id" not in message:
                continue
            line = lines.get(timeout=REQUEST_TIMEOUT)
            if line is None:
                raise RuntimeError("The server closed stdout early")
            response = parse_line(line)
            if response.get("id") != message["id"]:
                raise RuntimeError(f"Expected an answer to request {message['id']}: {response!r}")
            by_id[message["id"]] = response
        server.stdin.close()
        # After the last answer nothing else may arrive: the notification got no reply
        # and the server wrote nothing unprompted. EOF on stdin ends the server.
        for line in iter(lambda: lines.get(timeout=REQUEST_TIMEOUT), None):
            if line.strip():
                raise RuntimeError(f"Unexpected extra output on stdout: {line[:200]!r}")
        server.wait(timeout=REQUEST_TIMEOUT)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()
    if server.returncode != 0:
        raise RuntimeError(f"The server exited with status {server.returncode}")
    return by_id


def tool_text(result, name):
    if result.get("isError"):
        raise RuntimeError(f"{name} returned an error: {result!r}")
    content = result.get("content", [])
    if not content:
        raise RuntimeError(f"{name} returned no content")
    return json.loads(content[0]["text"])


def validate_overview(result, fixture):
    overview = tool_text(result, "analyze_file")
    if overview["file_path"] != str(fixture) or overview["size"] != fixture.stat().st_size:
        raise RuntimeError("analyze_file returned an overview of a different file")
    if overview["sha256"] != hashlib.sha256(fixture.read_bytes()).hexdigest():
        raise RuntimeError("analyze_file returned the wrong SHA-256")
    if not overview.get("next_steps"):
        raise RuntimeError("analyze_file returned no next_steps")


def validate_drill_down(result):
    page = tool_text(result, "query_analysis")
    if page.get("cache") != "hit":
        raise RuntimeError(f"query_analysis was not answered from the cache: {page.get('cache')!r}")
    if not any(SAMPLE_URL in str(item.get("value")) for item in page.get("items", [])):
        raise RuntimeError(f"query_analysis did not find the sample string: {page!r}")


def validate_responses(by_id, fixture):
    for request_id in (1, 2, 3, 4, 5):
        response = by_id.get(request_id)
        if response is None or "error" in response or "result" not in response:
            raise RuntimeError(f"MCP request {request_id} failed: {response!r}")
    initialized = by_id[1]["result"]
    if initialized.get("protocolVersion") != PROTOCOL_VERSION:
        raise RuntimeError(f"Unexpected protocol version: {initialized.get('protocolVersion')!r}")
    if initialized.get("serverInfo", {}).get("name") != "file-scanner":
        raise RuntimeError("initialize named a different server")
    if not initialized.get("instructions"):
        raise RuntimeError("initialize returned no instructions")
    names = {tool["name"] for tool in by_id[2]["result"]["tools"]}
    if names != EXPECTED_TOOLS:
        raise RuntimeError(
            f"tools/list differs: missing {sorted(EXPECTED_TOOLS - names)}, "
            f"unexpected {sorted(names - EXPECTED_TOOLS)}"
        )
    validate_overview(by_id[3]["result"], fixture)
    tool_text(by_id[4]["result"], "analyze_file sections")
    validate_drill_down(by_id[5]["result"])


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    with tempfile.TemporaryDirectory(prefix="file-scanner-mcp-") as directory:
        base = Path(directory).resolve()
        fixture = base / "samples" / "sample.txt"
        fixture.parent.mkdir()
        fixture.write_text(f"File scanner MCP smoke test.\nSee {SAMPLE_URL} for details.\n", encoding="utf-8")
        validate_responses(exchange(sys.argv[1], fixture, base / "cache"), fixture)
        print("MCP handshake, tools/list (17 tools), analyze_file overview and cached query_analysis passed")


if __name__ == "__main__":
    main()
