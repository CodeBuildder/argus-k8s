#!/usr/bin/env bash
set -Eeuo pipefail

sog_url="${SOG_URL:-http://127.0.0.1:8010}"
seed="${DEMO_SEED:-42}"
sequence=0
services=("service/storefront/checkout" "service/payments/payment-api" "service/orders/order-api")
iso_offset() { python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=int(sys.argv[1]))).isoformat().replace("+00:00","Z"))' "$1"; }

while true; do
  sleep "${DEMO_FEED_INTERVAL_SECONDS:-20}"
  sequence=$((sequence + 1))
  entity_id="${services[$((sequence % ${#services[@]}))]}"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  correlation_id="local-stream-${seed}-${sequence}-$(date -u +%H%M%S)"
  curl --fail --silent -X POST "${sog_url}/findings" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg id "argus-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg corr "${correlation_id}" --argjson seed "${seed}" '{event_id:$id,type:"finding",source:"argus",timestamp:$ts,entity_id:$entity,severity:"medium",correlation_id:$corr,replayed:true,payload:{assessment:"Seeded runtime anomaly replay",provenance:"replayed",demo_data:true,seed:$seed}}')" >/dev/null
  curl --fail --silent -X POST "${sog_url}/findings" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg id "phoenix-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg corr "${correlation_id}" --arg healthy "$(iso_offset 0)" --arg fault "$(iso_offset 1)" --arg detected "$(iso_offset 2)" --arg decision "$(iso_offset 3)" --arg approval "$(iso_offset 4)" --arg recovered "$(iso_offset 5)" --arg verified "$(iso_offset 6)" --argjson seed "${seed}" '{event_id:$id,type:"finding",source:"phoenix",timestamp:$ts,entity_id:$entity,severity:"medium",correlation_id:$corr,payload:{outcome:"verified_recovery",description:"Synthetic health check passed after bounded recovery",provenance:"simulator",domain:"simulator",demo_data:true,seed:$seed,approval_required:false,evidence_source:"Synthetic simulator + replay feed",metrics:{detection_ms:1000,recovery_ms:1000,availability_percent:"not measured"},lifecycle:[{stage:"healthy",timestamp:$healthy,source:"synthetic feed",evidence:"Synthetic service baseline established",status:"simulated"},{stage:"fault_injected",timestamp:$fault,source:"Phoenix simulator",evidence:"Bounded synthetic fault activated; no cluster mutation",status:"simulated"},{stage:"detection",timestamp:$detected,source:"replayed Argus",evidence:"Seeded runtime anomaly replay published",status:"replayed"},{stage:"decision",timestamp:$decision,source:"Sentinel simulator policy",evidence:"Bounded recovery selected for the synthetic scenario",status:"simulated"},{stage:"human_approval",timestamp:$approval,source:"governance policy",evidence:"Approval not required for bounded simulator action",status:"not required"},{stage:"recovery",timestamp:$recovered,source:"Phoenix simulator",evidence:"Synthetic health check passed after bounded recovery",status:"simulated"},{stage:"verification",timestamp:$verified,source:"synthetic health check",evidence:"Simulator recovery verified; availability not measured",status:"simulated"}]}}')" >/dev/null
done
