# Sentinel Platform — Judge Submission Kit

> **Core message:** Detect early. Break safely. Recover before customers feel it—with
> humans governing high-risk actions.

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

## The 2:50 recording script

### Shot 1 — The problem · `0:00–0:09`

**SHOW:** Sentinel home page, with the headline and Live Risk card visible.

**DO BEFORE SPEAKING:** Place the cursor in empty space. Do not click anything.

**SAY:**

> Most platforms wait for an alert or outage. Sentinel doesn’t. It looks for threats and
> failures before customers have to find them.

**END ON:** The unchanged Sentinel home page.

---

### Shot 2 — Connect the platform · `0:09–0:22`

**SHOW:** The Sentinel **How it works** overlay.

**DO BEFORE SPEAKING:** Click **How it works** and wait until the overlay is fully open.

**DO WHILE SPEAKING:** Move the cursor slowly from **Argus** to **SOG**, then to
**Sentinel + OpenAI** as you name them.

**SAY:**

> Argus watches admission, the kernel, runtime, and network using Kyverno, eBPF, Falco,
> and Cilium—catching suspicious behavior close to where it starts.

**END ON:** The cursor resting over **Sentinel + OpenAI**.

---

### Shot 3 — Explain control · `0:22–0:32`

**SHOW:** Keep the same **How it works** overlay open.

**DO BEFORE SPEAKING:** Move the cursor to **Human governance**.

**DO WHILE SPEAKING:** Point to **Human governance** for the first two sentences, then
move to **Phoenix** for the final sentence.

**SAY:**

> Phoenix deliberately tests failures before real outages happen. Safe fixes run
> automatically; risky actions wait for a person. Every recovery has to prove it worked.

**END ON:** The cursor resting over **Phoenix**.

---

### Shot 4 — Show Argus evidence · `0:32–0:45`

**SHOW:** Argus threat detail for the highest-severity seeded threat.

**DO BEFORE SPEAKING:** Switch to the prepared Argus tab and open the threat detail.
Make sure source, severity, affected resource, and recommended response are visible.

**DO WHILE SPEAKING:** Point once to the original evidence, then once to the recommended
response. Do not scroll rapidly.

**SAY:**

> Here, Argus caught suspicious runtime behavior near the kernel and enforcement path.
> It can contain the workload early, preserve evidence, and stop a larger incident.

**END ON:** The recommended response and evidence visible together.

---

### Shot 5 — Show Phoenix verification · `0:45–0:58`

**SHOW:** Phoenix completed resilience scenario or agent run matching the demo resource.

**DO BEFORE SPEAKING:** Switch to the prepared Phoenix tab. Open a completed run and
make its provenance, recovery action, and verified result visible.

**DO WHILE SPEAKING:** Point to the recovery result only when saying “verified.”

**SAY:**

> Phoenix doesn’t wait for an outage report. It injects a bounded fault, diagnoses the
> weakness, recovers the service, and verifies its health.

**END ON:** The completed and verified recovery result.

---

### Shot 6 — Show the shared SOG · `0:58–1:12`

**SHOW:** Sentinel home page with both specialist-agent cards and the central SOG card.

**DO BEFORE SPEAKING:** Return to Sentinel and wait for **SOG LIVE**. Ensure Argus,
Phoenix, entities, relationships, evidence, and incidents are visible.

**DO WHILE SPEAKING:** Point from Argus to the SOG, then from the SOG to Phoenix. Finish
by pointing to the entity and relationship counts.

**SAY:**

> Sentinel connects both sides. It knows what Argus stopped, what Phoenix tested, which
> services depend on each other, and—using OpenAI—what actually needs our attention.

**END ON:** The complete three-card Argus → SOG → Phoenix view.

---

### Shot 7 — Prove the lifecycle · `1:12–1:30`

**SHOW:** Sentinel at <http://127.0.0.1:5175>. In **01 · Operations Evidence**, click the
green **OPEN INCIDENTS** control beside the live record count.

**DO BEFORE SPEAKING:** In the panel that opens from the right, click any listed incident
that says it has lifecycle records. This opens its operator-ready report. Pause on the
executive summary, impact, decision, recovery, verification, and operator follow-up.
Then scroll inside the right-hand panel until **Resilience proof timeline** is visible.
The main page behind the panel will look dark and blurred; that is expected.

**DO WHILE SPEAKING:** Begin on the operator-ready report. Then scroll slowly through
**Healthy → Fault injected → Detection → Decision → Human approval → Recovery →
Verification**. The final stage must be visible at the end of the narration.

**SAY:**

> One incident gives us the complete report—what happened, what was affected, what the
> system decided, and how recovery was verified. We don’t call it fixed until the final
> health check passes.

**END ON:** Keep the right-hand panel open with **Verification** visible, including its
result and evidence source.

---

### Shot 8 — Prove honesty and explainability · `1:30–1:42`

**SHOW:** The incident provenance label, followed by the Live Risk explanation popup.

**DO BEFORE SPEAKING:** Keep the provenance badge visible.

**DO WHILE SPEAKING:** Point to the provenance badge during the first sentence. Then
close the incident, click **Live Risk**, and reveal its supporting score evidence.

**SAY:**

> We’re also clear about what’s real and what’s simulated. Every record shows its source,
> and every risk score opens into the evidence behind it.

**END ON:** The Live Risk score breakdown and supporting records.

---

### Shot 9 — Show GPT-5.6 working · `1:42–2:02`

**SHOW:** Sentinel's **OpenAI Evidence Briefing** panel with a completed briefing already
visible. Generate it before recording; do not wait for the API on camera.

**DO BEFORE SPEAKING:** Frame both the **OpenAI Evidence Briefing** heading and the
generated posture explanation. Keep at least one evidence-backed recommendation visible.

**DO WHILE SPEAKING:** Point to the current-posture summary, then its recommended next
action. Do not scroll faster than the viewer can read.

**SAY:**

> GPT-5.6 works inside the product, not just behind the demo. It turns current SOG
> evidence into incident assessments, risk explanations, threat-hunting help, and clear
> operator briefings like this one. The model explains the decision, while policy and
> human approval still control high-impact action.

**END ON:** The evidence-backed recommendation in the OpenAI briefing.

---

### Shot 10 — Explain how Codex built it · `2:02–2:25`

**SHOW:** The repository in your IDE. Put `BUILD_WEEK.md` on the left and the Git commit
history or pull-request list on the right. Make Phases 7–16 visible.

**DO BEFORE SPEAKING:** Prepare this view before recording. Do not show `.env`, API keys,
private chat content, or unrelated repositories.

**DO WHILE SPEAKING:** Point to the deterministic platform demo, live k3s proof,
provenance timeline, persistence, readiness panel, and submission phase as you describe
the workflow.

**SAY:**

> I used Codex as my engineering partner across all three repositories. We turned three
> separate agents into one repeatable platform demo, designed the shared evidence
> contracts, added guarded k3s automation, built the lifecycle and provenance UI, and
> wrote the tests and setup path. Every phase is tracked through an issue, commit, and
> reviewable pull request.

**END ON:** `BUILD_WEEK.md` with the completed phase record and commit history both visible.

---

### Shot 11 — Show the proof artifact · `2:25–2:43`

**SHOW:** Prefer `artifacts/demo-platform/latest-live-demo.md`. If no live artifact is
available, show `artifacts/demo-platform/latest-demo.md` and keep its simulator/replay
label visible.

**DO BEFORE SPEAKING:** Open the prepared scorecard and frame the provenance, recovery,
availability, and timing rows.

**DO WHILE SPEAKING:** Point to cross-agent correlation first, then the live-only
availability measurement.

**SAY:**

> This local demo makes that loop repeatable. Our guarded k3s mode goes further: real
> runtime detection, a real Chaos Mesh fault, and measured recovery and availability.

**END ON:** The evidence scorecard with provenance visible.

---

### Shot 12 — Close · `2:43–2:50`

**SHOW:** Sentinel home page and its main headline.

**DO BEFORE SPEAKING:** Return to Sentinel. Close every popup and place the cursor in
empty space.

**SAY:**

> Find it early, fix it safely, verify the outcome, and keep people in control.

**END ON:** Hold the Sentinel headline silently for one full second, then fade to black.

The voice-over is paced for conversational delivery and targets 2:50. The official limit
is under three minutes, leaving ten seconds of export and upload safety margin.

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

Sentinel continuously finds threats and resilience weaknesses close to their source,
contains or recovers them before impact spreads, verifies the outcome, and keeps humans
in control of high-risk actions.

### Inspiration

Most security and reliability products begin after something has already gone wrong.
Security tools report an attack, reliability tools report an outage, and operators still
have to reconstruct the connection. We wanted a proactive evidence loop that continuously
searches for both compromise and failure, acts close to the source, and proves the result.

### What it does

Argus uses Kyverno admission controls, eBPF and Falco runtime visibility, and Cilium
network enforcement to detect and contain suspicious behavior before it spreads through
the application. Phoenix continuously injects bounded failures so weaknesses are found
before customers encounter them, then diagnoses, recovers, and verifies service health.
Sentinel connects both through the Sentinel Operations Graph (SOG), uses OpenAI to
explain fleet posture and prioritize decisions, and routes consequential actions through
explicit human approval.

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

### How Codex accelerated the build

Codex served as an engineering partner across the Argus, Phoenix, Sentinel, and SOG
repositories. It helped turn separate agents into one deterministic demo, design and
implement the shared evidence contracts, build guarded k3s and Chaos Mesh workflows,
add persistence and presentation preflight, iterate on the dashboards, and create tests
and single-path documentation. We used an issue → branch → test → commit → pull-request
workflow for every phase, while making the product and safety decisions explicitly.

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
- [ ] Video explicitly explains what was built, how Codex accelerated it, and how GPT-5.6 works inside it
- [ ] Final cut is under three minutes—target 2:50—and legible at 1080p
- [ ] Video audio is clear at normal laptop volume
- [ ] Run `/feedback` in the primary Codex build thread and save the required Session ID
- [ ] Upload the final video publicly to YouTube and verify it plays while signed out
- [ ] Devpost cover, screenshots, repository link, and setup path are included
