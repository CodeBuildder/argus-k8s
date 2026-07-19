# OpenAI Build Week — Development Record

This document distinguishes the pre-existing Sentinel platform from the functionality
added during the OpenAI Build Week submission period, which began July 13, 2026.

## Existing foundation

Before Build Week, the project already included:

- Argus runtime detection, enrichment, reasoning, remediation, and command console
- Phoenix chaos injection, error analysis, root-cause reconstruction, blast-radius
  reasoning, self-healing agent, and verified-recovery dashboard
- Sentinel repository scaffolding for the primary multi-agent supervisor
- Sentinel Platform schemas, adapters, and Sentinel Operations Graph (SOG) service

The existing foundation provides the domain agents and infrastructure. It is not being
represented as work created during Build Week.

## Build Week extension

The Build Week objective is to turn the separate systems into one coordinated autonomous
resilience platform:

> Argus defends workloads, Phoenix continuously exercises and restores them, and Sentinel
> coordinates both through a shared Sentinel Operations Graph (SOG)—with humans governing risky actions.

Work started during the submission period includes:

- Argus findings and entity posture integration with the shared Sentinel Operations Graph (SOG)
- Phoenix outcome integration with the shared Sentinel Operations Graph (SOG)
- Sentinel platform positioning and cross-agent architecture documentation
- A seeded randomized incident generator for exploratory demos and deterministic replays
- Input validation, distribution summaries, and automated tests for generated incidents
- Repository and UI build-quality fixes discovered during Codex-assisted verification
- Migration of every active Argus AI workflow to the OpenAI Responses API

## Phase record

| Phase | Scope | Tracking |
|---|---|---|
| Phase 1 | Reproducible randomized incident generation and repository stabilization | Issue #90 / PR #91 |
| Phase 2 | Argus findings and entity posture synchronization with the Sentinel Operations Graph (SOG) | Issue #92 |
| Phase 3 | Cluster-free setup, launch, simulation, and troubleshooting path | Issue #94 |
| Phase 4 | Guarded real-cluster demo automation and evidence collection | Issue #98 / PR #100 |
| Phase 5 | Real-cluster agent and console lifecycle integration | Issue #101 / PR #102 |
| Phase 6 | OpenAI-native reasoning, configuration, deployment, UI status, and documentation | Issue #103 / PR #104 |
| Phase 7 | One-command deterministic Argus, Phoenix, Sentinel, and SOG judge demo | Issue #110 |
| Phase 8 | Auditable judge evidence scorecard and JSON/Markdown run artifacts | Issue #112 |
| Phase 9 | Cluster-free full-platform judge demo and explicit live-k3s command | Issue #114 |
| Phase 10 | Guarded live k3s detection, chaos, recovery, correlation, and measured evidence | Issue #116 |
| Phase 11 | Judge onboarding doctor, single-path setup, and rehearsal diagnostics | Issue #118 |
| Phase 12 | Canonical resilience lifecycle and unambiguous evidence provenance | Argus #120 / Sentinel #63 |
| Phase 13 | Persistent Phoenix scenarios, approvals, agent runs, and restart history | Phoenix #73 |
| Phase 14 | Judge-facing read-only platform readiness panel | Argus #122 / Sentinel #65 |
| Phase 15 | Unified 30-second judge-facing system explanation | Sentinel #67 |
| Phase 16 | Under-three-minute judge story, recording safeguards, screenshots, and Devpost submission kit | Issue #124 |

### Phase 16 — judge video and submission kit

`SUBMISSION_KIT.md` is the single rehearsal and submission source. It provides a timed
2:55 recording plan with the exact screen, action, and narration for every shot; truthful
portable-versus-live claim boundaries; recording fallbacks; a screenshot list; copy-ready
Devpost sections; and a final quality gate. The story explicitly covers what was built,
how Codex accelerated the multi-repository engineering workflow, how GPT-5.6 operates
inside the product, OpenAI reasoning, the SOG, verified recovery, evidence provenance,
and human governance without requiring the presenter to improvise.

### Phase 15 — 30-second system explanation

Sentinel now includes a responsive **How it works** presentation overlay. Its five-stage
flow explains Argus observation, SOG connection, Sentinel and OpenAI decision support,
human authorization, and Phoenix recovery plus verification. It includes a ready-to-speak
24-second narration, explicit autonomy boundaries, and all four provenance labels.

### Phase 12 — truthful resilience proof timeline

Every correlated judge incident can now carry the same seven-stage lifecycle: Healthy,
Fault injected, Detection, Decision, Human approval, Recovery, and Verification. The
live producer supplies actual timestamps, measured detection/recovery durations, HTTP
availability, experiment ID, and evidence source. Human approval occurs only after
observed Argus evidence exists. The portable producer supplies a visually equivalent
timeline, but every stage is explicitly simulator/replay provenance and availability is
reported as not measured. Sentinel renders four mutually exclusive labels—Live
Observed, Synthetic Simulator, Live Chaos Mesh, and Replayed Evidence—and never infers
missing proof stages.

### Phase 11 — judge onboarding and rehearsal doctor

`make doctor` and `make doctor-live` are read-only entry points for the portable and live
proofs. They validate the sibling repository layout, required tools, secret-safe OpenAI
configuration status, runtime availability, local console dependencies, and—only in
live mode—the complete k3s stack. Each run ends with an unambiguous verdict and exact
next command. `setup.md`, the root README, and Make help now present the same choose-one
path and distinguish replay/simulator claims from observed/live-chaos measurements.

### Phase 10 — observed live-cluster proof

`make demo-platform-live-dry-run` validates the actual k3s security, chaos, agent, and
SOG stack without changing it. `make demo-platform-live` then requires two explicit
human confirmations, creates an isolated two-replica service, waits for observed Argus
evidence, asks Phoenix to create one real Chaos Mesh PodChaos, continuously measures
HTTP availability, verifies Kubernetes replacement and full readiness, and publishes
only the verified cross-agent lifecycle to Sentinel. The resulting JSON/Markdown
scorecard distinguishes observed/live-chaos provenance from the portable simulator.

### Phase 9 — portable judge demo

`make demo-platform` now defaults to the cluster-free path: a disposable local SOG,
real local product services, an explicitly synthetic three-node topology, deterministic
Argus and Phoenix lifecycles, and a bounded dynamic feed. `make demo-platform-live`
preserves the k3s-backed integration proof. The split prevents “safe” from being confused
with “cluster-free” and keeps simulated evidence visually useful without mislabeling it
as live production telemetry.

### Phase 8 — judge evidence report

Every successful deterministic platform run now emits a concise PASS scorecard and
stores the verified lifecycle as JSON and Markdown. The report preserves correlation,
sources, provenance, seed, governance, OpenAI configuration, recovery state, and measured
orchestration timings. It explicitly avoids claiming live detection latency or 100%
availability from replayed and simulated evidence.

### Phase 7 — deterministic platform demo

`make demo-platform` provides one guarded path through the complete product. It starts
or reuses the three consoles and their APIs, connects them to the shared SOG, publishes
seeded Argus replay evidence and a Phoenix simulator recovery outcome for the same
resource, and verifies the resulting cross-agent incident through Sentinel before
declaring the demo ready. `make demo-platform-dry-run` validates the environment without
starting processes, forwarding ports, publishing evidence, or changing cluster state.

### Phase 6 — OpenAI-native reasoning

Every active AI workflow now uses the OpenAI Responses API: incident assessment,
operator summaries, natural-language threat hunting, risk forecasting, and chat.
High-stakes alerts route to GPT-5.6, while frequent operator workflows use efficient
GPT-5.6 variants. Model failures and malformed responses continue to fail closed to
human review. Kubernetes deployment, network egress, health status, tests, and setup
instructions use `OPENAI_API_KEY` consistently.

### Phase 2 — SOG integration

Phase 2 turns Argus into a reliable producer of cross-agent operational state:

- Every accepted Falco alert receives a deterministic UUID derived from the alert's
  deduplication identity and timestamp.
- Findings carry the original evidence plus Argus's severity, confidence, assessment,
  recommended response, false-positive judgment, and blast-radius estimate.
- Eligible non-false-positive decisions update the affected pod or node posture.
- Duplicate SOG writes are safe and reported as idempotent outcomes.
- Transient transport and server failures receive one bounded retry.
- Disabled or unavailable SOG services never interrupt Argus enrichment,
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
