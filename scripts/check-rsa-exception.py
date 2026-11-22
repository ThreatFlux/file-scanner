#!/usr/bin/env python3
"""Guard stable RSA and the reviewed public-key-only YARA verification surface."""

import hashlib
from pathlib import Path
import re
import tomllib


def require(condition, message):
    if not condition:
        raise RuntimeError(f"RSA source policy needs review: {message}")


def main():
    """Verify the stable graph, sole public verification caller and removed waiver."""
    root = Path(__file__).resolve().parent.parent
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    rsa = [package for package in packages if package["name"] == "rsa"]
    require(len(rsa) == 1 and rsa[0]["version"] == "0.10.0", "RSA version/graph changed")
    users = [
        package for package in packages
        if any(dependency.split()[0] == "rsa" for dependency in package.get("dependencies", []))
    ]
    yara = [package for package in users if package["name"] == "yara-x"]
    require(len(yara) == 1 and yara[0]["version"] == "1.24.0",
            "YARA-X verification parent changed")
    require("source" not in yara[0], "YARA-X no longer uses reviewed local source")
    shim = [package for package in users if package["name"] == "threatflux-threat-detection"]
    # The published producer contributes the pkcs1v15 feature for YARA.
    # All 16 Rust files match the tagged source and invoke no RSA API.
    require(len(users) == 2 and len(shim) == 1 and shim[0]["version"] == "0.3.0"
            and shim[0].get("checksum") == "d31a0389d4c7c1bc8cf35aa031df610b7c70cd4ec5f7bc0d31b77fac46f37740",
            "RSA feature-only producer shim changed")
    for relative in (".cargo/audit.toml", "deny.toml"):
        require("RUSTSEC-2023-0071" not in (root / relative).read_text(),
                "obsolete RSA waiver was restored")

    vendor = root / "vendor/yara-x-1.24.0"
    crypto = vendor / "src/modules/utils/crypto.rs"
    require(
        hashlib.sha256(crypto.read_bytes()).hexdigest()
        == "7266c5b6ef5a169344127ab5dcbc6537b3deb84f74a5ff5bb61322eda3e2d09e",
        "reviewed public-key verification source changed",
    )
    rsa_use = re.compile(r"\brsa\s*::|\b(?:use|extern\s+crate)\s+rsa\b|\bRsaPrivateKey\b")
    for directory in (vendor / "src", root / "src"):
        for source in directory.rglob("*.rs"):
            if source != crypto:
                require(not rsa_use.search(source.read_text()), f"new RSA use in {source.relative_to(root)}")
    print("Stable RSA policy: version, reviewed feature-only producer shim and public-key-only YARA source verified; old advisory waiver removed")


if __name__ == "__main__":
    main()
