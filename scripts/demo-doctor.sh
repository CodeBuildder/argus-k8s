#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-local}"
phoenix_root="${PHOENIX_ROOT:-${repo_root}/../sentinel-stack/phoenix}"
sentinel_root="${SENTINEL_ROOT:-${repo_root}/../sentinel-stack/sentinel}"
platform_root="${SENTINEL_PLATFORM_ROOT:-${repo_root}/../sentinel-stack/sentinel-platform}"
failures=0
warnings=0

usage() {
  cat <<'EOF'
Usage: scripts/demo-doctor.sh [local|live]

  local  Check the recommended cluster-free judge path (default).
  live   Check the observed k3s proof, including deployed stack readiness.

This command is read-only. It never starts services, installs dependencies, publishes
evidence, creates Kubernetes resources, or injects a fault.
EOF
}

pass() { printf '  [PASS] %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; warnings=$((warnings + 1)); }
fail_check() { printf '  [FAIL] %s\n' "$1"; failures=$((failures + 1)); }

check_command() {
  local command_name="$1" remedy="$2"
  if command -v "${command_name}" >/dev/null 2>&1; then
    pass "${command_name} is installed"
  else
    fail_check "${command_name} is missing — ${remedy}"
  fi
}

check_directory() {
  local path="$1" label="$2" remedy="$3"
  if [[ -d "${path}" ]]; then pass "${label}: ${path}"; else fail_check "${label} is missing — ${remedy}"; fi
}

case "${mode}" in
  local|live) ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

echo "Sentinel judge demo doctor"
echo "  Mode:      ${mode}"
echo "  Read-only: yes"
echo "  Argus:     ${repo_root}"
echo
echo "==> Repository layout"
check_directory "${repo_root}/agent" "Argus" "run this command from the argus-k8s checkout"
check_directory "${phoenix_root}/dashboard" "Phoenix" "clone Phoenix at ../sentinel-stack/phoenix or set PHOENIX_ROOT"
check_directory "${sentinel_root}/dashboard" "Sentinel" "clone Sentinel at ../sentinel-stack/sentinel or set SENTINEL_ROOT"
check_directory "${platform_root}/world_model" "Sentinel Platform / SOG" "clone Sentinel Platform at ../sentinel-stack/sentinel-platform or set SENTINEL_PLATFORM_ROOT"

echo
echo "==> Required tools"
for tool in bash curl jq npm python3 lsof; do
  check_command "${tool}" "install ${tool} and retry"
done

if [[ -n "${OPENAI_API_KEY:-}" ]] || { [[ -f "${repo_root}/.env" ]] && grep -Eq '^[[:space:]]*OPENAI_API_KEY=.+' "${repo_root}/.env"; }; then
  pass "OPENAI_API_KEY is configured (value not displayed)"
else
  warn "OPENAI_API_KEY is not configured — deterministic proof works, but the OpenAI evidence briefing will be unavailable"
fi

if [[ "${mode}" == "local" ]]; then
  echo
  echo "==> Portable demo runtime"
  check_command docker "install Docker or start OrbStack"
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    pass "Docker-compatible runtime is reachable"
  else
    fail_check "Docker-compatible runtime is not reachable — start Docker or OrbStack"
  fi
else
  echo
  echo "==> Local console dependencies"
  [[ -x "${repo_root}/.venv/bin/python" ]] && pass "Argus Python environment is installed" || fail_check "Argus Python environment is missing — run: make setup-local"
  [[ -d "${repo_root}/ui/node_modules" ]] && pass "Argus UI dependencies are installed" || fail_check "Argus UI dependencies are missing — run: make setup-local"
  [[ -x "${sentinel_root}/.venv/bin/python" ]] && pass "Sentinel Python environment is installed" || fail_check "Sentinel Python environment is missing — run: make -C ${sentinel_root} setup-local"
  [[ -d "${sentinel_root}/dashboard/node_modules" ]] && pass "Sentinel UI dependencies are installed" || fail_check "Sentinel UI dependencies are missing — run Sentinel setup-local"
  [[ -d "${phoenix_root}/dashboard/node_modules" ]] && pass "Phoenix UI dependencies are installed" || fail_check "Phoenix UI dependencies are missing — run: npm --prefix ${phoenix_root}/dashboard install"

  echo
  echo "==> Live k3s stack"
  check_command kubectl "install kubectl and configure the argus context"
  if command -v kubectl >/dev/null 2>&1; then
    if LIVE_DEMO_DRY_RUN=true PHOENIX_ROOT="${phoenix_root}" SENTINEL_ROOT="${sentinel_root}" \
      bash "${repo_root}/scripts/demo-platform-live-proof.sh"; then
      pass "live security, chaos, agent, and SOG preflight passed"
    else
      fail_check "live stack preflight failed — follow the component named above, then retry"
    fi
  fi
fi

echo
echo "==> Verdict"
if ((failures > 0)); then
  echo "NOT READY — ${failures} blocking check(s), ${warnings} warning(s)."
  exit 1
fi

echo "READY — 0 blocking checks, ${warnings} warning(s)."
if [[ "${mode}" == "local" ]]; then
  echo "Next: make demo-platform"
else
  echo "Next: make demo-platform-live"
  echo "The live command will still require the exact context and INJECT LIVE FAULT."
fi
