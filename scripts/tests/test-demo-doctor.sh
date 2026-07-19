#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
doctor="${repo_root}/scripts/demo-doctor.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_contains() { grep -Fq -- "$1" "${doctor}" || fail "missing $2"; }

bash -n "${doctor}"
bash "${doctor}" --help | grep -Fq 'This command is read-only.' || fail "help does not state mutation boundary"
if bash "${doctor}" invalid >/dev/null 2>&1; then fail "invalid mode was accepted"; fi

assert_contains 'OPENAI_API_KEY is configured (value not displayed)' "secret-safe credential check"
assert_contains 'LIVE_DEMO_DRY_RUN=true' "live dry-run delegation"
assert_contains 'Next: make demo-platform' "portable next action"
assert_contains 'Next: make demo-platform-live' "live next action"
assert_contains 'INJECT LIVE FAULT' "live approval reminder"

echo "Judge demo doctor tests passed."
