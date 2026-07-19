# Sentinel Platform Resilience Proof: PASS

> Committed judge sample. This is deterministic replay + simulator evidence, not a live
> Kubernetes or production claim.

**Mode:** deterministic replay + simulator  
**Correlation:** `sample-portable-checkout-egress`  
**Resource:** `service/storefront/checkout`

## Evidence scorecard

| Measurement | Result |
|---|---|
| Argus evidence | Published and correlated |
| Phoenix recovery | `verified_recovery` |
| Sentinel correlation | Verified across Argus + Phoenix |
| Recovery | Simulator outcome verified |
| Availability | Not measured in portable mode |
| Human approval | Not required — bounded simulator action |
| Sources | Argus + Phoenix |
| Provenance | Replayed + simulator |
| Experiment | Deterministic seed 42 |

## Operator-ready incident report

| Field | Evidence-backed result |
|---|---|
| Detection | Blocked suspicious egress from checkout |
| Affected resource | `checkout` |
| Impact | Critical evidence attached to checkout; no wider impact claimed without evidence |
| Root cause | Not established by the supplied evidence |
| Decision | Bounded simulator recovery selected |
| Governance | Approval not required for bounded simulator action |
| Recovery | Network latency recovered within SLO |
| Verification | Simulator outcome verified; availability not measured |
| Evidence source | Synthetic simulator + replay fixture |

## Seven-stage proof

| Stage | Source | Result |
|---|---|---|
| Healthy | Synthetic fixture | Service baseline established |
| Fault injected | Phoenix simulator | Synthetic fault activated; no cluster mutation |
| Detection | Replayed Argus | Evaluation finding published |
| Decision | Sentinel simulator policy | Bounded recovery selected |
| Human approval | Governance policy | Not required for bounded simulator action |
| Recovery | Phoenix simulator | Network latency recovered within SLO |
| Verification | Synthetic health check | Recovery verified; availability not measured |

## Interpretation

A real local SOG and all three product services processed an explicitly synthetic
topology, replayed Argus evidence, and Phoenix simulator outcome. No Kubernetes API or
live fault was used. Run `make demo-platform-live` for separately labeled observed and
live-Chaos evidence with measured availability.
