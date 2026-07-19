# Sentinel Platform — Judge Submission Kit

> **Core message:** Autonomous resilience through AI—with humans governing high-risk actions.

This is the single recording and submission guide. Run commands from `argus-k8s/`.
The primary video uses the portable demo so the recording is deterministic. A short,
clearly labeled live-k3s proof supplies the measured infrastructure claim.

## Before recording

```bash
make doctor
make demo-platform
```

Open and arrange these tabs in this order:

1. Sentinel — <http://127.0.0.1:5175>
2. Argus — <http://127.0.0.1:5173>
3. Phoenix — <http://127.0.0.1:5174>
4. Portable scorecard — `artifacts/demo-platform/latest-demo.md`
5. Live scorecard — `artifacts/demo-platform/latest-live-demo.md`, if captured

Recording settings: 1920×1080, browser zoom 90–100%, notifications off, cursor visible,
and no terminal containing `.env` or credentials. Wait for **SOG LIVE** before recording.

## The 1:55 judge cut

Read the narration naturally. Do not add improvised architecture detail.

| Time | Show | Action | Narration |
|---:|---|---|---|
| 0:00–0:08 | Sentinel hero | Hold on the headline and live risk card. | “Production systems fail in two ways: attacks compromise them, and infrastructure breaks beneath them. Today those signals live in separate tools.” |
| 0:08–0:20 | **How it works** overlay | Select **How it works**. Let the five stages remain visible. | “Sentinel closes that gap. Argus turns runtime security telemetry into evidence. The Sentinel Operations Graph connects it to affected services. Sentinel uses OpenAI to explain and prioritize the decision.” |
| 0:20–0:29 | Same overlay | Point to **Human governance**, then **Phoenix**. | “Safe, proven recovery can run autonomously. High-impact action waits for a human. Phoenix then restores the service and verifies the result.” |
| 0:29–0:42 | Argus | Open the highest-severity threat detail. Pause on source, severity, resource, and recommended action. | “Here Argus has detected suspicious workload behavior, preserved the original evidence, mapped the blast radius, and produced an evidence-grounded response—not just another alert.” |
| 0:42–0:55 | Phoenix | Open the matching resilience scenario or completed run. Pause on its provenance and result. | “Phoenix exercises the affected service, classifies the failure, executes a bounded recovery, and records whether health was actually restored.” |
| 0:55–1:10 | Sentinel command center | Return to Sentinel. Point to Argus, Phoenix, entity count, and relationship count. | “Sentinel combines both specialist agents inside the SOG. This is live application state: connected entities, relationships, evidence, and correlated incidents refresh continuously.” |
| 1:10–1:28 | Sentinel incident drawer | Open the correlated incident. Scroll through Healthy → Fault injected → Detection → Decision → Approval → Recovery → Verification. | “One incident now explains the full resilience lifecycle. Every stage carries its timestamp, evidence source, and outcome, so an operator can audit exactly why the system acted.” |
| 1:28–1:40 | Provenance labels and risk explanation | Point to the provenance badge, then open score evidence. | “The product never disguises demo data. Replay, simulator, live observation, and live Chaos Mesh are visibly distinct. Fleet risk is explainable down to its supporting records.” |
| 1:40–1:50 | Live scorecard, or portable scorecard when unavailable | Show provenance, recovery, availability, and timings. | “The repeatable demo verifies cross-agent correlation. Our guarded k3s proof separately measures real Chaos Mesh recovery and HTTP availability.” |
| 1:50–1:55 | Sentinel hero | Return to the headline. No cursor movement. | “Sentinel is autonomous resilience through AI—with humans governing high-risk actions.” |

The narration is intentionally below two minutes, leaving room for clicks and visual pauses.

## Truthful on-screen claims

| If the badge says | You may say | Never say |
|---|---|---|
| **Replayed evidence** | “Argus replay evidence processed by the real local services” | “A live attack is happening” |
| **Synthetic simulator** | “Phoenix verified recovery in the simulator” | “Kubernetes recovered this workload” |
| **Live observed** | “Observed from the authorized k3s security stack” | “Synthetic” or “replayed” |
| **Live Chaos Mesh** | “A real, approved Chaos Mesh fault in the isolated demo namespace” | “Production outage” |

Only quote an availability percentage from `latest-live-demo.md`. The portable proof
verifies recovery but deliberately reports availability as **not measured**.

## Shot safety and fallback plan

| Moment | Primary | If it fails during recording |
|---|---|---|
| Platform startup | Already-running `make demo-platform` | Run `make doctor`; use the last portable scorecard while services restart |
| OpenAI briefing | Generate once before recording | Use the previously generated briefing; never wait on an API call on camera |
| Dynamic feed | Wait for the next 20-second update | Refresh Sentinel once; continue with the seeded incident |
| Live k3s proof | Use a previously completed, timestamped live scorecard | Show the portable scorecard and state that live proof is a separate guarded mode |
| UI navigation | Use prepared tabs | Cut directly to the target tab; do not troubleshoot on camera |

## Required screenshots

Capture clean 16:9 images with no browser chrome where possible:

- Sentinel hero with **SOG LIVE**, live risk, and both specialist agents reporting
- **How it works** five-stage system story
- Argus threat detail with evidence and recommended response
- Phoenix completed recovery with provenance and verification
- Sentinel correlated incident with the seven-stage proof timeline
- Sentinel score explanation with supporting evidence
- Presentation preflight showing **Ready to present**
- Live proof scorecard showing observed/live-chaos provenance and measured availability

Use the Sentinel hero as the Devpost cover. Use the seven-stage incident timeline as the
technical proof image.

## Devpost copy

### One-line pitch

Sentinel coordinates AI-native security and resilience agents to detect threats, recover
services, verify outcomes, and keep humans in control of high-risk actions.

### Inspiration

Security tools can identify an attack while reliability tools independently detect an
outage, but operators still have to reconstruct what happened and decide whether an
automated response is safe. We wanted one accountable evidence loop that understands
both compromise and failure.

### What it does

Argus converts Falco, Cilium, Kyverno, and Kubernetes telemetry into reasoned security
evidence. Phoenix continuously tests resilience, diagnoses faults, performs bounded
recovery, and verifies service health. Sentinel connects both through the Sentinel
Operations Graph (SOG), uses OpenAI to explain fleet posture and prioritize decisions,
and routes consequential actions through explicit human approval.

### How we built it

The platform consists of three cooperating products and a shared operational graph.
Argus and Phoenix publish structured, provenance-marked findings. The SOG connects those
records to services, dependencies, incidents, and trust state. Sentinel correlates the
evidence and exposes the complete lifecycle in one command center. The portable demo
runs the real local services with deterministic replay and simulation; the guarded k3s
path uses Cilium, Falco, Kyverno, Chaos Mesh, and continuous HTTP probes.

### How OpenAI is used

OpenAI reasoning turns structured operational evidence into concise incident assessment,
risk explanation, threat-hunting assistance, and operator briefings. The model advises
inside an evidence-bounded workflow; deterministic policy and human approval remain the
control plane for high-impact action.

### What makes it different

Sentinel does not stop at detection or claim recovery because an action was dispatched.
It connects security and resilience evidence, visibly distinguishes synthetic from live
proof, and closes the loop only after recovery is verified.

### Challenges

The hardest problem was making autonomy trustworthy: correlating different evidence
models, preserving provenance, bounding destructive actions, surviving service restarts,
and presenting complex infrastructure state without hiding uncertainty.

### Accomplishments

- One-command, cross-agent demonstration with auditable JSON and Markdown evidence
- Guarded live-k3s fault injection with explicit approval and isolated cleanup
- Seven-stage resilience proof from healthy state through verification
- Persistent Phoenix scenario, approval, and agent-run history
- Read-only presentation preflight across all platform dependencies
- Clear human-governance boundaries and evidence provenance throughout the UI

### What's next

Next we will extend policy learning from operator decisions, add broader workload and
cloud adapters, benchmark recovery objectives across longer test windows, and validate
the platform in multi-cluster environments.

## Final quality gate

- [ ] `make doctor` reports ready
- [ ] `make demo-platform` reaches **PLATFORM LOCAL PROOF: PASS**
- [ ] Sentinel shows SOG live and both agents reporting
- [ ] The prepared correlated incident opens correctly
- [ ] OpenAI briefing is generated before recording
- [ ] No secrets, usernames, notifications, or unrelated tabs are visible
- [ ] Every spoken metric is visible on screen
- [ ] Portable and live provenance are never mixed
- [ ] Final cut is under two minutes and legible at 1080p
- [ ] Video audio is clear at normal laptop volume
- [ ] Devpost cover, screenshots, repository link, and setup path are included

