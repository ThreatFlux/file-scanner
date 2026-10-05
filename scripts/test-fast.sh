#!/usr/bin/env bash
# Fast unit tests; make test-all also runs integrations and package-security.
set -euo pipefail
cargo test --locked --workspace --all-features --lib --bins --quiet "$@"
