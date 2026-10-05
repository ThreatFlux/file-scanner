#!/usr/bin/env bash
# Reclaim unused SDK space only on disposable GitHub-hosted Linux runners.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != Linux ]]; then
  echo "Disk cleanup is limited to GitHub-hosted Linux runners."
  exit 0
fi
df -h /
# Keep clang/LLVM, Node, CodeQL, Cargo caches, Docker layers, and /tmp inputs.
sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc /usr/local/.ghcup \
  /usr/share/swift /usr/local/julia* /usr/share/gradle-* /usr/share/apache-maven-* \
  /usr/share/sbt /opt/az /opt/microsoft /usr/share/miniconda
sudo apt-get clean
df -h /
