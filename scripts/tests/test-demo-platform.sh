#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="${repo_root}/scripts/demo-platform.sh"
local_script="${repo_root}/scripts/demo-platform-local.sh"
renderer="${repo_root}/scripts/render-demo-report.sh"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/demo-report-test.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

bash -n "${script}"
bash -n "${local_script}"
bash -n "${repo_root}/scripts/seed-platform-local.sh"
bash -n "${repo_root}/scripts/platform-local-feed.sh"
bash -n "${renderer}"

grep -q 'DEMO_PLATFORM_DRY_RUN' "${script}"
grep -q 'DEMO_PLATFORM_EXIT_AFTER_READY' "${script}"
grep -q 'correlation_id="judge-demo-' "${script}"
grep -q 'provenance.*replayed' "${script}"
grep -q 'provenance.*simulator' "${script}"
grep -q 'Press Ctrl-C to stop only processes started by this command' "${script}"
grep -q 'PLATFORM RESILIENCE PROOF: PASS' "${script}"
grep -q 'availability percentage not measured' "${script}"
grep -q 'sentinel_ui_ok' "${script}"
grep -q 'listener_cwd.*expected_cwd' "${script}"
grep -q '5175/api/health' "${script}"
grep -q 'Kubernetes API calls:       0' "${local_script}"
grep -q 'PHOENIX_LOCAL_DEMO=true' "${local_script}"
grep -q 'synthetic cluster topology' "${local_script}"
grep -q 'docker run --rm' "${local_script}"
grep -q 'demo-data.*synthetic' "${repo_root}/scripts/seed-platform-local.sh"

jq -n '{
  schema_version: "1.0", verdict: "PASS", run_id: "test", generated_at: "2026-07-18T00:00:00Z",
  correlation: {id: "judge-demo-test", verified: true, sources: ["argus", "phoenix"]},
  timings: {argus_evidence_publish_ms: 10, phoenix_recovery_publish_ms: 20, sentinel_correlation_ms: 30, total_lifecycle_ms: 60},
  recovery: {result: "verified_recovery", availability: "recovery verified; availability percentage not measured"},
  governance: {approval_required: false, reason: "bounded simulator action"},
  openai: {configured: true, briefing_generated: false},
  evidence: {provenance: ["replayed", "simulator"], seed: 42},
  interpretation: "Deterministic test proof."
}' >"${tmp_dir}/report.json"
bash "${renderer}" "${tmp_dir}/report.json" "${tmp_dir}/report.md"
grep -q 'Sentinel Platform Resilience Proof: PASS' "${tmp_dir}/report.md"
grep -q 'availability percentage not measured' "${tmp_dir}/report.md"

echo "demo-platform orchestration tests passed"
