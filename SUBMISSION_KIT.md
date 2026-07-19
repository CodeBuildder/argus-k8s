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

## How to record this

Record the screen first, then add the narration as a voice-over. This removes the pressure
of clicking and speaking perfectly at the same time.

For every shot below:

1. Move to the requested screen.
2. Complete the instruction under **DO BEFORE SPEAKING**.
3. Wait until the page is still and readable.
4. Read only the text under **SAY**.
5. Complete **DO WHILE SPEAKING** slowly, if present.
6. Stop speaking at **END ON** and leave the screen still for half a second.

Do not read the **SHOW**, **DO**, or **END ON** instructions aloud.

## The 1:55 recording script

### Shot 1 — The problem · `0:00–0:08`

**SHOW:** Sentinel home page, with the headline and Live Risk card visible.

**DO BEFORE SPEAKING:** Place the cursor in empty space. Do not click anything.

**SAY:**

> Production systems fail in two ways: attacks compromise them, and infrastructure
> breaks beneath them. Today those signals live in separate tools.

**END ON:** The unchanged Sentinel home page.

---

### Shot 2 — Connect the platform · `0:08–0:20`

**SHOW:** The Sentinel **How it works** overlay.

**DO BEFORE SPEAKING:** Click **How it works** and wait until the overlay is fully open.

**DO WHILE SPEAKING:** Move the cursor slowly from **Argus** to **SOG**, then to
**Sentinel + OpenAI** as you name them.

**SAY:**

> Sentinel closes that gap. Argus turns runtime security telemetry into evidence. The
> Sentinel Operations Graph connects it to affected services. Sentinel uses OpenAI to
> explain and prioritize the decision.

**END ON:** The cursor resting over **Sentinel + OpenAI**.

---

### Shot 3 — Explain control · `0:20–0:29`

**SHOW:** Keep the same **How it works** overlay open.

**DO BEFORE SPEAKING:** Move the cursor to **Human governance**.

**DO WHILE SPEAKING:** Point to **Human governance** for the first two sentences, then
move to **Phoenix** for the final sentence.

**SAY:**

> Safe, proven recovery can run autonomously. High-impact action waits for a human.
> Phoenix then restores the service and verifies the result.

**END ON:** The cursor resting over **Phoenix**.

---

### Shot 4 — Show Argus evidence · `0:29–0:42`

**SHOW:** Argus threat detail for the highest-severity seeded threat.

**DO BEFORE SPEAKING:** Switch to the prepared Argus tab and open the threat detail.
Make sure source, severity, affected resource, and recommended response are visible.

**DO WHILE SPEAKING:** Point once to the original evidence, then once to the recommended
response. Do not scroll rapidly.

**SAY:**

> Here Argus detected suspicious workload behavior, preserved the original evidence,
> mapped the blast radius, and produced an evidence-grounded response—not just another
> alert.

**END ON:** The recommended response and evidence visible together.

---

### Shot 5 — Show Phoenix verification · `0:42–0:55`

**SHOW:** Phoenix completed resilience scenario or agent run matching the demo resource.

**DO BEFORE SPEAKING:** Switch to the prepared Phoenix tab. Open a completed run and
make its provenance, recovery action, and verified result visible.

**DO WHILE SPEAKING:** Point to the recovery result only when saying “verified.”

**SAY:**

> Phoenix exercises the affected service, classifies the failure, executes a bounded
> recovery, and records whether health was actually restored.

**END ON:** The completed and verified recovery result.

---

### Shot 6 — Show the shared SOG · `0:55–1:10`

**SHOW:** Sentinel home page with both specialist-agent cards and the central SOG card.

**DO BEFORE SPEAKING:** Return to Sentinel and wait for **SOG LIVE**. Ensure Argus,
Phoenix, entities, relationships, evidence, and incidents are visible.

**DO WHILE SPEAKING:** Point from Argus to the SOG, then from the SOG to Phoenix. Finish
by pointing to the entity and relationship counts.

**SAY:**

> Sentinel combines both specialist agents inside the SOG. This is live application
> state: connected entities, relationships, evidence, and correlated incidents refresh
> continuously.

**END ON:** The complete three-card Argus → SOG → Phoenix view.

---

### Shot 7 — Prove the lifecycle · `1:10–1:28`

**SHOW:** Sentinel at <http://127.0.0.1:5175>. Close **How it works**, then look directly
below the large headline section. In the row of five number cards, click the far-right
card labeled **OPEN INCIDENTS**. It appears after **NAMESPACES**.

**DO BEFORE SPEAKING:** In the panel that opens from the right, click any listed incident
that says it has lifecycle records. This replaces the list with that incident's detail.
Scroll inside the right-hand panel until the heading **Resilience proof timeline** is
visible. The main page behind the panel will look dark and blurred; that is expected.

**DO WHILE SPEAKING:** Scroll slowly through **Healthy → Fault injected → Detection →
Decision → Human approval → Recovery → Verification**. The final stage must be visible
when you say “why the system acted.”

**SAY:**

> One incident explains the full resilience lifecycle. Every stage carries its
> timestamp, evidence source, and outcome, so an operator can audit exactly why the
> system acted.

**END ON:** Keep the right-hand panel open with **Verification** visible, including its
result and evidence source.

---

### Shot 8 — Prove honesty and explainability · `1:28–1:40`

**SHOW:** The incident provenance label, followed by the Live Risk explanation popup.

**DO BEFORE SPEAKING:** Keep the provenance badge visible.

**DO WHILE SPEAKING:** Point to the provenance badge during the first sentence. Then
close the incident, click **Live Risk**, and reveal its supporting score evidence.

**SAY:**

> The product never disguises demo data. Replay, simulator, live observation, and live
> Chaos Mesh are visibly distinct. Fleet risk is explainable down to its supporting
> records.

**END ON:** The Live Risk score breakdown and supporting records.

---

### Shot 9 — Show the proof artifact · `1:40–1:50`

**SHOW:** Prefer `artifacts/demo-platform/latest-live-demo.md`. If no live artifact is
available, show `artifacts/demo-platform/latest-demo.md` and keep its simulator/replay
label visible.

**DO BEFORE SPEAKING:** Open the prepared scorecard and frame the provenance, recovery,
availability, and timing rows.

**DO WHILE SPEAKING:** Point to cross-agent correlation first, then the live-only
availability measurement.

**SAY:**

> The repeatable demo verifies cross-agent correlation. Our guarded k3s proof separately
> measures real Chaos Mesh recovery and HTTP availability.

**END ON:** The evidence scorecard with provenance visible.

---

### Shot 10 — Close · `1:50–1:55`

**SHOW:** Sentinel home page and its main headline.

**DO BEFORE SPEAKING:** Return to Sentinel. Close every popup and place the cursor in
empty space.

**SAY:**

> Sentinel is autonomous resilience through AI—with humans governing high-risk actions.

**END ON:** Hold the Sentinel headline silently for one full second, then fade to black.

The voice-over contains 215 words. At a calm pace, it leaves enough time for the screen
actions and short pauses while keeping the final cut below two minutes.

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
