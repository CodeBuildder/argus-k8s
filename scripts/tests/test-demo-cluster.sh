#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$repo_root/scripts/demo-cluster.sh"

expect_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $description" >&2
    exit 1
  fi
}

bash -n "$script"
bash -n "$repo_root/cluster/test-diverse-threats.sh"
bash "$script" --help >/dev/null
expect_failure "rejects default namespace" env DEMO_NAMESPACE=default bash "$script" --dry-run
expect_failure "rejects system namespace" env DEMO_NAMESPACE=kube-system bash "$script" --dry-run
expect_failure "rejects invalid DNS label" env DEMO_NAMESPACE=Bad_Name bash "$script" --dry-run
expect_failure "rejects short evidence window" env DEMO_WAIT_SECONDS=1 bash "$script" --dry-run
expect_failure "rejects long evidence window" env DEMO_WAIT_SECONDS=301 bash "$script" --dry-run
expect_failure "rejects unknown arguments" bash "$script" --destroy-everything

grep -q 'kubectl port-forward --address 127.0.0.1' "$script"
grep -q 'http://127.0.0.1:5173/api/health' "$script"
grep -q 'namespace_created=true' "$script"
grep -q 'Press Ctrl-C to stop the console' "$script"

echo "demo-cluster guard tests passed"
