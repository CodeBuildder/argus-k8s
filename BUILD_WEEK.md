# OpenAI Build Week — Development Record

This document distinguishes the pre-existing Sentinel platform from the functionality
added during the OpenAI Build Week submission period, which began July 13, 2026.

## Existing foundation

Before Build Week, the project already included:

- Argus runtime detection, enrichment, reasoning, remediation, and command console
- Phoenix chaos injection, failure diagnosis, self-healing agent, and dashboard
- Sentinel repository scaffolding for the primary multi-agent supervisor
- Sentinel Platform schemas, adapters, and World Model service

The existing foundation provides the domain agents and infrastructure. It is not being
represented as work created during Build Week.

## Build Week extension

The Build Week objective is to turn the separate systems into one coordinated autonomous
resilience platform:

> Argus defends workloads, Phoenix continuously exercises and restores them, and Sentinel
> coordinates both through a shared World Model—with humans governing risky actions.

Work started during the submission period includes:

- Argus findings and entity posture integration with the shared World Model
- Phoenix outcome integration with the shared World Model
- Sentinel platform positioning and cross-agent architecture documentation
- A seeded randomized incident generator for exploratory demos and deterministic replays
- Input validation, distribution summaries, and automated tests for generated incidents
- Repository and UI build-quality fixes discovered during Codex-assisted verification

## Phase record

| Phase | Scope | Tracking |
|---|---|---|
| Phase 1 | Reproducible randomized incident generation and repository stabilization | Issue #90 / PR #91 |
| Phase 2 | Argus findings and entity posture synchronization with the Sentinel World Model | Issue #92 |

### Phase 2 — World Model integration

Phase 2 turns Argus into a reliable producer of cross-agent operational state:

- Every accepted Falco alert receives a deterministic UUID derived from the alert's
  deduplication identity and timestamp.
- Findings carry the original evidence plus Argus's severity, confidence, assessment,
  recommended response, false-positive judgment, and blast-radius estimate.
- Eligible non-false-positive decisions update the affected pod or node posture.
- Duplicate World Model writes are safe and reported as idempotent outcomes.
- Transient transport and server failures receive one bounded retry.
- Disabled or unavailable World Model services never interrupt Argus enrichment,
  reasoning, audit logging, or remediation.

## Why the randomized generator exists

The generator serves two different testing modes:

- **Exploration:** omit the seed to produce a new mixture of threats, affected workloads,
  blast radii, evidence sources, and recommended actions.
- **Evaluation:** retain the returned seed to replay the same incident selection in tests,
  judge demonstrations, and regression investigations.

Supported scenarios are `mixed`, `human_approval`, and `attack_chain`. Inputs are bounded
to 1–100 incidents per request so a demo cannot accidentally overwhelm the in-memory store.

## Codex and GPT-5.6 collaboration

Codex is being used as an engineering collaborator across repository analysis,
architecture decisions, implementation, testing, documentation, and demo preparation.
The primary Build Week thread includes the repository audit, product-scope decision,
randomizer design, implementation changes, and verification results.

Key human decisions include:

- Positioning Phoenix as continuous synthetic resilience testing, not generic chaos tooling
- Targeting autonomous recovery with explicit human control over risky operations
- Prioritizing a coherent cross-agent incident loop over adding disconnected features
- Requiring both randomized exploration and deterministic replay for credible evaluation

The `/feedback` Codex Session ID and qualifying commit references will be added before the
submission deadline.

## Verification

```bash
python3 -m venv .venv
.venv/bin/pip install -r agent/requirements.txt
make test
```

Run a new randomized incident batch:

```bash
make simulate-threats THREAT_COUNT=10 THREAT_SCENARIO=mixed
```

Replay a known batch:

```bash
make simulate-threats THREAT_COUNT=10 THREAT_SCENARIO=mixed THREAT_SEED=20260717
```
