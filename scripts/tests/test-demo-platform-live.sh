#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
driver="${repo_root}/scripts/demo-platform-live-proof.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_contains() {
  local pattern="$1" description="$2"
  grep -Fq -- "${pattern}" "${driver}" || fail "missing ${description}"
}

bash -n "${driver}"
assert_contains 'LIVE_DEMO_DRY_RUN' "non-mutating dry-run"
assert_contains 'INJECT LIVE FAULT' "explicit fault approval"
assert_contains 'LIVE_DEMO_CONTEXT' "exact context approval"
assert_contains 'fault_seconds <= 30' "bounded fault duration"
assert_contains 'sentinel-live-demo' "isolated default namespace"
assert_contains 'replicas: 2' "redundant disposable target"
assert_contains 'mode:"one"' "single-replica blast radius"
assert_contains 'get podchaos "${backend_ref}"' "real Chaos Mesh object verification"
assert_contains 'replacement_ready' "replacement readiness verification"
assert_contains 'measured_availability_percent' "measured availability evidence"
assert_contains 'provenance:"observed"' "observed Argus provenance"
assert_contains 'provenance:"live_chaos"' "live Phoenix provenance"
assert_contains 'stage:"human_approval"' "human approval lifecycle stage"
assert_contains 'stage:"verification"' "verification lifecycle stage"
assert_contains 'metrics:{detection_ms:' "measurable proof metrics"
assert_contains 'Observed Argus evidence is now present.' "just-in-time approval after detection"
assert_contains 'delete namespace "${namespace}"' "isolated cleanup boundary"

echo "Live platform demo guard tests passed."
