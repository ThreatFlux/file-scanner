#!/usr/bin/env python3
"""Stamp the release version into the server.json template.

The committed server.json is a template whose three version strings hold the
placeholder 0.0.0. The release workflow stamps the real version into a copy
and uploads it as a release asset. Every refusal exits non-zero and writes
nothing.
"""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLACEHOLDER = "0.0.0"
# Same pattern as the "Determine version" step in .github/workflows/release.yml.
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$")
CARGO_NAME = "threatflux-file-scanner"
IMAGE = "ghcr.io/threatflux/file-scanner"
DOCKER_ARG = "ARG VERSION=" + PLACEHOLDER


class StampError(Exception):
    """The version or the template is not acceptable."""


def render(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def packages_of(data, registry):
    if not all(isinstance(p, dict) for p in data["packages"]):
        raise StampError("every entry in packages must be an object")
    if len(data["packages"]) != 2:
        raise StampError("packages must hold exactly one cargo and one oci package")
    found = [p for p in data["packages"] if p.get("registryType") == registry]
    if len(found) != 1:
        raise StampError(f"expected exactly one {registry} package, found {len(found)}")
    return found[0]


def locate(data):
    """Return the (object, key) slots that hold the three version strings."""
    if not isinstance(data, dict) or not isinstance(data.get("packages"), list):
        raise StampError("template must be an object with a packages list")
    cargo = packages_of(data, "cargo")
    oci = packages_of(data, "oci")
    if cargo.get("identifier") != CARGO_NAME:
        raise StampError(f"cargo package identifier must be {CARGO_NAME}")
    prefix = IMAGE + ":"
    ident = oci.get("identifier")
    if not isinstance(ident, str) or not ident.startswith(prefix):
        raise StampError(f"oci identifier must be {prefix}<tag>")
    return [(data, "version"), (cargo, "version"), (oci, "identifier")]


def current(slot):
    obj, key = slot
    value = obj.get(key)
    return value.removeprefix(IMAGE + ":") if key == "identifier" else value


def check_template(text):
    data = json.loads(text)
    slots = locate(data)
    for obj, key in slots:
        if current((obj, key)) != PLACEHOLDER:
            raise StampError(f"{key} must be the placeholder {PLACEHOLDER}")
    if render(data) != text:
        raise StampError("template formatting differs from 2-space JSON with a trailing newline")
    return data


def stamp(text, version):
    if not VERSION_RE.fullmatch(version):
        raise StampError(f"invalid version format: {version!r}")
    data = check_template(text)
    top, cargo, oci = locate(data)
    top[0][top[1]] = version
    cargo[0][cargo[1]] = version
    oci[0][oci[1]] = f"{IMAGE}:{version}"
    return render(data)


def check_dockerfile(text):
    flags = re.M | re.I
    count = len(re.findall(r"^" + re.escape(DOCKER_ARG) + r"$", text, re.M))
    if count != 2 or len(re.findall(r"^\s*ARG\b[^\n]*\bVERSION=", text, flags)) != 2:
        raise StampError(f"Dockerfile must hold exactly two '{DOCKER_ARG}' defaults")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=pathlib.Path, default=ROOT / "server.json")
    parser.add_argument("--dockerfile", type=pathlib.Path, default=ROOT / "Dockerfile")
    parser.add_argument("--version")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        text = args.template.read_bytes().decode("utf-8")
        if args.check:
            check_template(text)
            check_dockerfile(args.dockerfile.read_bytes().decode("utf-8"))
            print("server.json and Dockerfile hold the version placeholder")
            return 0
        if not args.version or args.output is None:
            parser.error("--version and --output are required unless --check is used")
        if args.output.resolve() == args.template.resolve():
            raise StampError("--output must not be the template file")
        result = stamp(text, args.version)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(result.encode("utf-8"))
    except (StampError, OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
