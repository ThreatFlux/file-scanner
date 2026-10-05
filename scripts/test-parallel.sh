#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${CI:-}" ]]; then
  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  exec "$script_dir/test-parallel-ci.sh" "$@"
fi
cargo test --locked --workspace --all-features "$@"
