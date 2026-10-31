#!/usr/bin/env python3
"""Guard the actual native zlib source/build selection, beyond package scanners."""

import hashlib
from pathlib import Path
import re
import tomllib


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    root = Path(__file__).resolve().parent.parent
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    relative = "vendor/libz-sys-1.1.31"
    require(manifest["patch"]["crates-io"]["libz-sys"]["path"] == relative, "Native zlib patch changed")
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    matches = [package for package in packages if package["name"] == "libz-sys"]
    require(len(matches) == 1 and matches[0]["version"] == "1.1.31", "Native wrapper needs re-review")
    require("source" not in matches[0], "Native zlib no longer resolves to reviewed local source")
    require(not any(dependency.split()[0] == "cmake"
                    for dependency in matches[0].get("dependencies", [])), "zlib-ng needs separate review")
    hashes = {
        "Cargo.toml": "8bb02320e7386c6706861d118ea25f29c532b35ef01ac707e428a90d5d6d72cb",
        "build.rs": "7526233222d96150a0e594fa9e7cc36a07716330bbd4f1461fedf7c87d866c48",
        "src/zlib/zlib.h": "818667d6ab6a37fe7469cb06a7f0cb2c2cb2f2c948a03e5accf1a4a74bf3020a",
        "src/zlib/crc32.c": "da37f3483e77c20f64c28cf55d62d7bed9d62af33eb401be906835d84539b9c9",
        "src/zlib/gzwrite.c": "31d0da140edf382b82b13e2d87a22f59e158d9014ee026459e01cf437d0ab07d",
    }
    for name, digest in hashes.items():
        require(hashlib.sha256((root / relative / name).read_bytes()).hexdigest() == digest,
                name + " needs re-review")
    docker = (root / "Dockerfile").read_text().split("FROM rust-base AS builder\n", 1)[1].split("\nFROM ", 1)[0]
    selection = re.search(r"^ENV LIBZ_SYS_STATIC=1$", docker, re.MULTILINE)
    require(selection and selection.start() < docker.index("cargo build --release"),
            "Production must use patched bundled zlib")
    print("Native zlib: reviewed local 1.3.2 CRC code, upstream gzip backport and static production selection verified")


if __name__ == "__main__":
    main()
