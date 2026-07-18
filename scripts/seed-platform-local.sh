#!/usr/bin/env bash
set -Eeuo pipefail

sog_url="${SOG_URL:-http://127.0.0.1:8010}"
argus_url="${ARGUS_URL:-http://127.0.0.1:8000}"
seed="${DEMO_SEED:-42}"
run_id="${DEMO_RUN_ID:-local-$(date -u +%Y%m%dT%H%M%SZ)}"

post_json() {
  curl --fail --silent --show-error -X POST "${sog_url}$1" \
    -H 'Content-Type: application/json' -d "$2" >/dev/null
}

entities='[
  {"entity_id":"node/demo/control-plane","entity_type":"node","name":"demo-control-plane","namespace":"cluster","labels":{"role":"control-plane","demo-data":"synthetic"}},
  {"entity_id":"node/demo/worker-a","entity_type":"node","name":"demo-worker-a","namespace":"cluster","labels":{"role":"worker","zone":"a","demo-data":"synthetic"}},
  {"entity_id":"node/demo/worker-b","entity_type":"node","name":"demo-worker-b","namespace":"cluster","labels":{"role":"worker","zone":"b","demo-data":"synthetic"}},
  {"entity_id":"service/edge/gateway","entity_type":"service","name":"gateway","namespace":"edge","labels":{"tier":"frontend","demo-data":"synthetic"},"slo_target":0.9995},
  {"entity_id":"service/storefront/web","entity_type":"service","name":"web","namespace":"storefront","labels":{"tier":"frontend","demo-data":"synthetic"}},
  {"entity_id":"service/storefront/checkout","entity_type":"service","name":"checkout","namespace":"storefront","labels":{"tier":"api","demo-data":"synthetic"},"slo_target":0.9999},
  {"entity_id":"service/payments/payment-api","entity_type":"service","name":"payment-api","namespace":"payments","labels":{"tier":"api","demo-data":"synthetic"},"slo_target":0.9999},
  {"entity_id":"service/payments/fraud-engine","entity_type":"service","name":"fraud-engine","namespace":"payments","labels":{"tier":"worker","demo-data":"synthetic"}},
  {"entity_id":"service/orders/order-api","entity_type":"service","name":"order-api","namespace":"orders","labels":{"tier":"api","demo-data":"synthetic"}},
  {"entity_id":"service/orders/order-worker","entity_type":"service","name":"order-worker","namespace":"orders","labels":{"tier":"worker","demo-data":"synthetic"}},
  {"entity_id":"service/data/postgres-primary","entity_type":"service","name":"postgres-primary","namespace":"data","labels":{"tier":"database","demo-data":"synthetic"}},
  {"entity_id":"service/data/redis-cache","entity_type":"service","name":"redis-cache","namespace":"data","labels":{"tier":"cache","demo-data":"synthetic"}},
  {"entity_id":"service/observability/prometheus","entity_type":"service","name":"prometheus","namespace":"observability","labels":{"tier":"monitoring","demo-data":"synthetic"}},
  {"entity_id":"service/argus-system/argus-agent","entity_type":"service","name":"argus-agent","namespace":"argus-system","labels":{"tier":"security","demo-data":"synthetic"}},
  {"entity_id":"service/phoenix-system/phoenix-agent","entity_type":"service","name":"phoenix-agent","namespace":"phoenix-system","labels":{"tier":"resilience","demo-data":"synthetic"}},
  {"entity_id":"pod/storefront/checkout-a","entity_type":"pod","name":"checkout-a","namespace":"storefront","labels":{"app":"checkout","demo-data":"synthetic"}},
  {"entity_id":"pod/payments/payment-api-a","entity_type":"pod","name":"payment-api-a","namespace":"payments","labels":{"app":"payment-api","demo-data":"synthetic"}},
  {"entity_id":"pod/orders/order-api-a","entity_type":"pod","name":"order-api-a","namespace":"orders","labels":{"app":"order-api","demo-data":"synthetic"}}
]'

while IFS= read -r entity; do post_json /entities "${entity}"; done < <(jq -c '.[]' <<<"${entities}")

edges='[
  ["service/edge/gateway","service/storefront/web","depends-on",0.8],
  ["service/storefront/web","service/storefront/checkout","depends-on",0.9],
  ["service/storefront/checkout","service/payments/payment-api","depends-on",1.0],
  ["service/storefront/checkout","service/orders/order-api","depends-on",0.9],
  ["service/payments/payment-api","service/payments/fraud-engine","depends-on",0.7],
  ["service/payments/payment-api","service/data/postgres-primary","depends-on",1.0],
  ["service/payments/fraud-engine","service/data/redis-cache","depends-on",0.6],
  ["service/orders/order-api","service/orders/order-worker","depends-on",0.8],
  ["service/orders/order-worker","service/data/postgres-primary","depends-on",0.9],
  ["service/storefront/checkout","service/data/redis-cache","depends-on",0.8],
  ["service/observability/prometheus","service/payments/payment-api","depends-on",0.4],
  ["service/argus-system/argus-agent","service/edge/gateway","depends-on",0.5],
  ["service/phoenix-system/phoenix-agent","service/storefront/checkout","depends-on",0.5],
  ["pod/storefront/checkout-a","node/demo/worker-a","runs-on",1.0],
  ["pod/payments/payment-api-a","node/demo/worker-b","runs-on",1.0],
  ["pod/orders/order-api-a","node/demo/worker-a","runs-on",1.0]
]'
while IFS= read -r edge; do
  post_json /edges "$(jq -nc --argjson row "${edge}" '{source_id:$row[0],target_id:$row[1],edge_type:$row[2],weight:$row[3]}')"
done < <(jq -c '.[]' <<<"${edges}")

curl --fail --silent --show-error -X POST "${argus_url}/simulate-threats" \
  -H 'Content-Type: application/json' \
  -d "{\"count\":12,\"scenario\":\"mixed\",\"seed\":${seed}}" >/dev/null

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for case_spec in \
  "checkout-egress|service/storefront/checkout|critical|Blocked suspicious egress from checkout|Network latency recovered within SLO" \
  "payment-shell|service/payments/payment-api|high|Unexpected shell detected in payment API|Payment replica replaced and health verified" \
  "orders-secret|service/orders/order-api|medium|Sensitive configuration read observed|Order API policy restored and verified"; do
  IFS='|' read -r case_name entity_id severity argus_summary phoenix_summary <<<"${case_spec}"
  correlation_id="local-${run_id}-${case_name}"
  post_json /findings "$(jq -nc --arg id "argus-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg severity "${severity}" --arg corr "${correlation_id}" --arg summary "${argus_summary}" --argjson seed "${seed}" '{event_id:$id,type:"finding",source:"argus",timestamp:$ts,entity_id:$entity,severity:$severity,correlation_id:$corr,replayed:true,payload:{finding_type:"falco_alert",assessment:$summary,provenance:"replayed",demo_data:true,seed:$seed}}')"
  post_json /findings "$(jq -nc --arg id "phoenix-${correlation_id}" --arg ts "${timestamp}" --arg entity "${entity_id}" --arg corr "${correlation_id}" --arg summary "${phoenix_summary}" --argjson seed "${seed}" '{event_id:$id,type:"finding",source:"phoenix",timestamp:$ts,entity_id:$entity,severity:"high",correlation_id:$corr,payload:{finding_type:"healing_action",outcome:"verified_recovery",description:$summary,provenance:"simulator",domain:"simulator",demo_data:true,approval_required:false,seed:$seed}}')"
done

echo "${run_id}"
