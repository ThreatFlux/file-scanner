#!/usr/bin/env bash
set -euo pipefail
hooks_dir=$(git rev-parse --path-format=absolute --git-path hooks)
mkdir -p "$hooks_dir"
for name in pre-commit commit-msg; do
  hook_path="$hooks_dir/$name"
  if [[ -e "$hook_path" ]] && ! rg -q 'file-scanner repository hook' "$hook_path"; then
    echo "Preserving existing $name hook at $hook_path" >&2
    continue
  fi
  cat > "$hook_path" <<'HOOK'
#!/usr/bin/env bash
# file-scanner repository hook; resolves the current worktree at invocation.
set -euo pipefail
repo_root=$(git rev-parse --show-toplevel)
repo_hook="$repo_root/.githooks/$(basename "$0")"
if [[ -x "$repo_hook" ]]; then
  exec "$repo_hook" "$@"
fi
HOOK
  chmod +x "$hook_path"
done
