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
    require(len(yara) == 1 and yara[0]["version"] == "1.23.0",
            "YARA-X verification parent changed")
    require("source" not in yara[0], "YARA-X no longer uses reviewed local source")
    shim = [package for package in users if package["name"] == "threatflux-threat-detection"]
    # This immutable published producer enables RSA's pkcs1v15 feature for
    # upstream YARA. Every Rust source file was checked: it invokes no RSA API.
    require(len(users) == 2 and len(shim) == 1 and shim[0]["version"] == "0.2.6"
            and shim[0].get("checksum") == "3bfc8941319d8f7ccfcccbbcdf489eb1a46bfa0daef0dd9b3c6d9550bd29d130",
            "RSA feature-only producer shim changed")
    for relative in (".cargo/audit.toml", "deny.toml"):
        require("RUSTSEC-2023-0071" not in (root / relative).read_text(),
                "obsolete RSA waiver was restored")
    standalone = tomllib.loads((root / "threatflux-package-security/Cargo.lock").read_text())["package"]
    require(not any(package["name"] == "rsa" for package in standalone), "standalone crate now uses RSA")

    vendor = root / "vendor/yara-x-1.23.0"
    crypto = vendor / "src/modules/utils/crypto.rs"
    require(
        hashlib.sha256(crypto.read_bytes()).hexdigest()
        == "19792550f440fd66573cf438e4e0bf717e704df35d476b7b872e5630bc8e099a",
        "reviewed public-key verification source changed",
    )
    rsa_use = re.compile(r"\brsa\s*::|\b(?:use|extern\s+crate)\s+rsa\b|\bRsaPrivateKey\b")
    for directory in (vendor / "src", root / "src", root / "threatflux-package-security/src"):
        for source in directory.rglob("*.rs"):
            if source != crypto:
                require(not rsa_use.search(source.read_text()), f"new RSA use in {source.relative_to(root)}")
    print("Stable RSA policy: version, reviewed feature-only producer shim and public-key-only YARA source verified; old advisory waiver removed")


if __name__ == "__main__":
    main()
