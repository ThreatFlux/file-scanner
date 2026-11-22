#!/usr/bin/env bash
# Fast unit tests; make test-all also runs integrations.
set -euo pipefail
cargo test --locked --workspace --all-features --lib --bins --quiet "$@"
