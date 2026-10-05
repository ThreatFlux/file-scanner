#!/usr/bin/env python3
"""Run a bounded MCP exchange against a caller-selected scanner build artifact."""

import hashlib
import json
from pathlib import Path
# This smoke test intentionally executes the local scanner with a fixed argument vector.
import subprocess  # nosec B404
import sys
import tempfile


def requests_for(fixture):
    return [
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "file-scanner-ci", "version": "1.0.0"},
            },
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "analyze_file",
                "arguments": {"file_path": str(fixture), "metadata": True, "hashes": True},
            },
        },
    ]


def exchange(binary, fixture):
    binary = Path(binary).resolve(strict=True)
    if binary.name != "file-scanner" or not binary.is_file():
        raise ValueError("Pass a local file-scanner build artifact")
    # The caller chooses its local build directory; executable/arguments are fixed,
    # shell expansion is disabled, and execution is bounded. No remote input is used.
    completed = subprocess.run(  # nosec B603
        ["./file-scanner", "mcp-stdio"], cwd=binary.parent,
        input="".join(json.dumps(message) + "\n" for message in requests_for(fixture)),
        text=True, capture_output=True, timeout=30, check=True, shell=False,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    return {response["id"]: response for response in responses if response.get("id") is not None}


def validate_analysis(result, fixture):
    if result.get("isError"):
        raise RuntimeError(f"analyze_file returned an error: {result!r}")
    content = result.get("content", [])
    if not content:
        raise RuntimeError("analyze_file returned no content")
    analysis = json.loads(content[0]["text"])
    if analysis["file_path"] != str(fixture) or analysis["metadata"]["file_size"] != fixture.stat().st_size:
        raise RuntimeError("analyze_file returned metadata for a different file")
    if analysis["hashes"]["sha256"] != hashlib.sha256(fixture.read_bytes()).hexdigest():
        raise RuntimeError("analyze_file returned the wrong SHA-256")


def validate_responses(by_id, fixture):
    for request_id in (1, 2, 3):
        response = by_id.get(request_id)
        if response is None or "error" in response or "result" not in response:
            raise RuntimeError(f"MCP request {request_id} failed: {response!r}")
    if not by_id[1]["result"].get("protocolVersion"):
        raise RuntimeError("Initialization returned no protocol version")
    if not any(tool["name"] == "analyze_file" for tool in by_id[2]["result"]["tools"]):
        raise RuntimeError("tools/list returned no analyze_file tool")
    validate_analysis(by_id[3]["result"], fixture)


def main():
    with tempfile.TemporaryDirectory(prefix="file-scanner-mcp-") as directory:
        fixture = Path(directory) / "sample.txt"
        fixture.write_text("File scanner MCP smoke test.\n", encoding="utf-8")
        validate_responses(exchange(sys.argv[1], fixture), fixture)
        print("MCP initialize, tools/list, and analyze_file passed")


if __name__ == "__main__":
    main()
