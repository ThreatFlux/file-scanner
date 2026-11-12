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
    relative = "vendor/libz-sys-1.1.33"
    require(manifest["patch"]["crates-io"]["libz-sys"]["path"] == relative, "Native zlib patch changed")
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    matches = [package for package in packages if package["name"] == "libz-sys"]
    require(len(matches) == 1 and matches[0]["version"] == "1.1.33", "Native wrapper needs re-review")
    require("source" not in matches[0], "Native zlib no longer resolves to reviewed local source")
    require(not any(dependency.split()[0] == "cmake"
                    for dependency in matches[0].get("dependencies", [])), "zlib-ng needs separate review")
    hashes = {
        "Cargo.toml": "73444b73ef59a62cdd205c8047f9e305782f737e0d68b1d0dfc324986527e40f",
        "build.rs": "7526233222d96150a0e594fa9e7cc36a07716330bbd4f1461fedf7c87d866c48",
        "src/zlib/zlib.h": "2c404dcaa08709c2a129aea18f3dad4fb5acc5cb52ef12b6223bf8e78c195801",
        "src/zlib/crc32.c": "dd941a0a499a27517e3be0624c2e0dc683f0591bf29dd1ed54e65443cb19beb6",
        "src/zlib/gzwrite.c": "e57621b7fffbc1909401acad13bef42adb5debee24a4c356a246f6b480e2db02",
    }
    for name, digest in hashes.items():
        require(hashlib.sha256((root / relative / name).read_bytes()).hexdigest() == digest,
                name + " needs re-review")
    docker = (root / "Dockerfile").read_text().split("FROM rust-base AS builder\n", 1)[1].split("\nFROM ", 1)[0]
    selection = re.search(r"^ENV LIBZ_SYS_STATIC=1$", docker, re.MULTILINE)
    require(selection and selection.start() < docker.index("cargo build --release"),
            "Production must use patched bundled zlib")
    print("Native zlib: reviewed official zlib1.4 CRC code and upstream-fixed gzip source and static production selection verified")


if __name__ == "__main__":
    main()
