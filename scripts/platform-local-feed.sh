#!/usr/bin/env bash
set -Eeuo pipefail

sog_url="${SOG_URL:-http://127.0.0.1:8010}"
seed="${DEMO_SEED:-42}"
sequence=0
services=("service/storefront/checkout" "service/payments/payment-api" "service/orders/order-api")

while true; do
  sleep "${DEMO_FEED_INTERVAL_SECONDS:-20}"
  sequence=$((sequence + 1))
  entity_id="${services[$((sequence % ${#services[@]}))]}"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  correlation_id="local-stream-${seed}-${sequence}-$(date -u +%H%M%S)"
  curl --fail --silent -X POST "${sog_url}/findings" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg id "argus-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg corr "${correlation_id}" --argjson seed "${seed}" '{event_id:$id,type:"finding",source:"argus",timestamp:$ts,entity_id:$entity,severity:"medium",correlation_id:$corr,replayed:true,payload:{assessment:"Seeded runtime anomaly replay",provenance:"replayed",demo_data:true,seed:$seed}}')" >/dev/null
  curl --fail --silent -X POST "${sog_url}/findings" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg id "phoenix-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg corr "${correlation_id}" --argjson seed "${seed}" '{event_id:$id,type:"finding",source:"phoenix",timestamp:$ts,entity_id:$entity,severity:"medium",correlation_id:$corr,payload:{outcome:"verified_recovery",description:"Synthetic health check passed after bounded recovery",provenance:"simulator",domain:"simulator",demo_data:true,seed:$seed}}')" >/dev/null
done
