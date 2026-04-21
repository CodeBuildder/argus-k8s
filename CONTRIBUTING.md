# Contributing to Argus

## Branch naming

| Type | Pattern | Example |
|---|---|---|
| New feature | `feat/module-N-description` | `feat/module-5-threat-feed` |
| Bug fix | `fix/short-description` | `fix/falco-arm64-ebpf` |
| Documentation | `docs/short-description` | `docs/adr-cilium` |
| Chore | `chore/short-description` | `chore/update-dependencies` |

## Commit style

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add kyverno blocked badge to threat feed
fix: resolve what_happened string vs array bug
docs: fill in architecture detection pipeline
chore: update agent requirements
test: add webhook deduplication tests
```

## Pull requests

- Every PR must reference an issue: `Closes #N` in the description
- Add module labels (`module-1` through `module-9`) and type labels (`ui`, `bug`, `enhancement`) at creation time
- Keep PRs focused — one issue per PR where possible

## Labels

| Label | When to use |
|---|---|
| `module-N` | The module this work belongs to |
| `enhancement` | New capability |
| `bug` | Something broken |
| `ui` | Console changes |
| `security` | Security policy or detection changes |
| `infrastructure` | Cluster or deployment changes |

## Before pushing

- Kyverno policies: run `kyverno test security/kyverno/` locally before committing
- Python agent: run `ruff check agent/src/` and `pytest agent/tests/` — both must pass
- No secrets, kubeconfigs, or `.env` files committed
- No `node_modules/` or `.venv/` directories committed

## Module order

Build in module order. Each module depends on the previous one being fully working. Do not start Module N+1 until Module N is running end-to-end on the cluster.

## Repository structure

```
argus-k8s/
├── cluster/          bootstrap scripts and namespace definitions
├── security/         Falco rules, Kyverno policies, Cilium network policies
├── observability/    Prometheus, Grafana, and Loki configuration
├── agent/            Python detection agent (FastAPI)
├── ui/               React console
└── docs/             Architecture, roadmap, and decision records
```

All architectural decisions are documented as ADRs in `docs/decisions/`. Before changing a fundamental tool choice, add or update the relevant ADR.
