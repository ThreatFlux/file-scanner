#!/usr/bin/env bash
# Fail on every unit, integration, or documentation failure.
set -euo pipefail
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
export RUST_TEST_THREADS=${RUST_TEST_THREADS:-2}
export CARGO_PROFILE_TEST_DEBUG=${CARGO_PROFILE_TEST_DEBUG:-0}
export CARGO_PROFILE_TEST_INCREMENTAL=${CARGO_PROFILE_TEST_INCREMENTAL:-false}
# Keep compiled dependencies between batches; deleting them forces full rebuilds.
cargo test --locked --workspace --all-features --lib --bins "$@"
cargo test --locked --workspace --all-features --tests "$@"
cargo test --locked --workspace --all-features --doc "$@"
cargo test --locked --manifest-path threatflux-package-security/Cargo.toml --all-features "$@"
