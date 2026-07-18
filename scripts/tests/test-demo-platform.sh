#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="${repo_root}/scripts/demo-platform.sh"

bash -n "${script}"

grep -q 'DEMO_PLATFORM_DRY_RUN' "${script}"
grep -q 'DEMO_PLATFORM_EXIT_AFTER_READY' "${script}"
grep -q 'correlation_id="judge-demo-' "${script}"
grep -q 'provenance.*replayed' "${script}"
grep -q 'provenance.*simulator' "${script}"
grep -q 'Press Ctrl-C to stop only processes started by this command' "${script}"

echo "demo-platform orchestration tests passed"
