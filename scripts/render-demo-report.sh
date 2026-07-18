#!/usr/bin/env bash
set -Eeuo pipefail

report_json="${1:?usage: render-demo-report.sh REPORT.json REPORT.md}"
report_markdown="${2:?usage: render-demo-report.sh REPORT.json REPORT.md}"

jq -e '
  .schema_version == "1.0" and
  .verdict == "PASS" and
  .correlation.verified == true and
  .correlation.sources == ["argus", "phoenix"] and
  .evidence.provenance == ["replayed", "simulator"] and
  .recovery.result == "verified_recovery"
' "${report_json}" >/dev/null

jq -r '
  "# Sentinel Platform Resilience Proof: \(.verdict)\n",
  "**Run:** `\(.run_id)`  ",
  "**Correlation:** `\(.correlation.id)`  ",
  "**Generated:** \(.generated_at)  ",
  "**Mode:** deterministic replay + simulator (no live Chaos Mesh)\n",
  "## Evidence scorecard\n",
  "| Measurement | Result |",
  "|---|---|",
  "| Argus evidence published | \(.timings.argus_evidence_publish_ms) ms |",
  "| Phoenix recovery published | \(.timings.phoenix_recovery_publish_ms) ms |",
  "| Sentinel correlation | \(.timings.sentinel_correlation_ms) ms |",
  "| Total verified lifecycle | \(.timings.total_lifecycle_ms) ms |",
  "| Recovery | \(.recovery.result) |",
  "| Availability claim | \(.recovery.availability) |",
  "| Human approval | \(if .governance.approval_required then "required" else "not required" end) — \(.governance.reason) |",
  "| OpenAI | \(if .openai.configured then "configured; briefing not invoked by this proof" else "not configured; deterministic proof still valid" end) |",
  "| Sources | \(.correlation.sources | join(" + ")) |",
  "| Provenance | \(.evidence.provenance | join(" + ")) |",
  "| Seed | \(.evidence.seed) |\n",
  "## Interpretation\n",
  .interpretation,
  "\n## Judge path\n",
  "1. Open Sentinel at <http://127.0.0.1:5175>.",
  "2. Open **Incidents** and select `\(.correlation.id)`.",
  "3. Follow the Argus evidence into the verified Phoenix recovery outcome."
' "${report_json}" >"${report_markdown}"
