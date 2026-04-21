# ADR 003: Falco for runtime threat detection

## Status
Accepted

## Context
Need a runtime security tool that detects suspicious behavior inside running containers
at the syscall level — not just static image scanning. Output must be structured and
machine-readable so the detection agent can process it programmatically.

## Decision
Use Falco deployed via Helm in eBPF mode with JSON webhook output.

## Rationale
- CNCF graduated project — industry standard for K8s runtime security
- Detects at syscall level: shell spawns, sensitive file reads, privilege escalation,
  network connections from unexpected processes
- Ships with a large default ruleset covering MITRE ATT&CK techniques
- Emits structured JSON events — directly consumable by the agent webhook receiver
- eBPF driver mode works on ARM64 without kernel module compilation
- Active ecosystem: rules contributed by the community, Falco plugins for cloud audit logs

## Rejected Alternatives
- Tetragon: Newer, eBPF-native, can enforce (kill processes) not just detect.
  Smaller rule ecosystem, less documentation. Considered as a stretch goal add-on.
- Tracee (Aqua): Good tool, smaller community, fewer resources when debugging
- KubeArmor: LSM-based enforcement, interesting but niche — limited docs for ARM64

## Consequences
Falco emits a high volume of events — the agent must implement alert deduplication and
suppression logic to avoid processing the same alert repeatedly.
Custom rules should be maintained in security/falco/custom-rules.yaml, not modified
in the default ruleset.
