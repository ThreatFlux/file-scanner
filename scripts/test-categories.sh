#!/usr/bin/env bash
set -euo pipefail
category=${1:-all}
if (( $# > 0 )); then shift; fi
case "$category" in
  unit) cargo test --locked --workspace --all-features --lib "$@" ;;
  hash) cargo test --locked --test hash_test "$@" ;;
  mcp) cargo test --locked --test 'mcp_*' --test mod mcp "$@" ;;
  analysis)
    cargo test --locked --test binary_parser_test --test npm_analysis_test \
      --test python_analysis_test --test dependency_analysis_test "$@"
    ;;
  integration) cargo test --locked --workspace --all-features --tests "$@" ;;
  all) cargo test --locked --workspace --all-features "$@" ;;
  help|--help|-h)
    echo "Usage: $0 [unit|hash|mcp|analysis|integration|all] [cargo test arguments]"
    ;;
  *) echo "Unknown category: $category" >&2; exit 2 ;;
esac
