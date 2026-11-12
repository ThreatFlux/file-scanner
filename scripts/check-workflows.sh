#!/usr/bin/env bash
set -euo pipefail
actionlint_bin=${ACTIONLINT_BIN:-actionlint}
yamllint_bin=${YAMLLINT_BIN:-yamllint}
"$actionlint_bin" -version | rg -q '^v?1\.7\.12$'
"$yamllint_bin" --version | rg -q '^yamllint 1\.38\.0$'
mapfile -t workflows < <(rg --files --hidden -g '*.yml' -g '*.yaml' .github/workflows)
"$yamllint_bin" -c .yamllint.yml "${workflows[@]}"
# The exact queue-field schema exception is scoped to auto-release.yml in
# .github/actionlint.yaml. All other workflow and shell checks remain enabled.
"$actionlint_bin" "${workflows[@]}"
