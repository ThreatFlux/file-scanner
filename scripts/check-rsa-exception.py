#!/usr/bin/env python3
"""Fail if the reviewed public-key-only RSA exception changes."""

import hashlib
from pathlib import Path
import re
import tomllib


def require(condition, message):
    if not condition:
        raise RuntimeError(f"RSA exception needs review: {message}")


def main():
    """Verify the RSA dependency graph, the reviewed source and that no new code uses RSA."""
    root = Path(__file__).resolve().parent.parent
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    rsa = [package for package in packages if package["name"] == "rsa"]
    require(len(rsa) == 1 and rsa[0]["version"] == "0.9.10", "RSA version/graph changed")
    users = [
        package for package in packages
        if any(dependency.split()[0] == "rsa" for dependency in package.get("dependencies", []))
    ]
    require(
        len(users) == 1 and users[0]["name"] == "yara-x" and users[0]["version"] == "1.22.0",
        "RSA has a new caller or YARA-X version",
    )
    require("source" not in users[0], "YARA-X no longer uses the reviewed local source")
    standalone = tomllib.loads((root / "threatflux-package-security/Cargo.lock").read_text())["package"]
    require(not any(package["name"] == "rsa" for package in standalone), "standalone crate now uses RSA")

    vendor = root / "vendor/yara-x-1.22.0"
    crypto = vendor / "src/modules/utils/crypto.rs"
    require(
        hashlib.sha256(crypto.read_bytes()).hexdigest()
        == "39dca4b54fba399f2b6773d0b4d1a142f212aaf17c5dd39daf97677e138ff3a4",
        "reviewed public-key verification source changed",
    )
    rsa_use = re.compile(r"\brsa\s*::|\b(?:use|extern\s+crate)\s+rsa\b|\bRsaPrivateKey\b")
    for directory in (vendor / "src", root / "src", root / "threatflux-package-security/src"):
        for source in directory.rglob("*.rs"):
            if source != crypto:
                require(not rsa_use.search(source.read_text()), f"new RSA use in {source.relative_to(root)}")
    print("Existing RSA exception: reviewed version, sole YARA-X caller, public-key-only source verified")


if __name__ == "__main__":
    main()
