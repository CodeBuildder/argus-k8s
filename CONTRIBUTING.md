# Contributing to Argus

## Branch naming
- `feat/module-1-cluster` — new features by module
- `fix/falco-arm64-ebpf` — bug fixes
- `docs/adr-cilium` — documentation

## Commit style
Follow conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `chore:` tooling, deps
- `test:` tests only

## Before pushing
- All Kyverno policies must pass `kyverno test` locally
- Python agent: `ruff check` and `pytest` must pass
- No secrets, kubeconfigs, or .env files committed

## Module order
Build in module order. Do not start Module N+1 until Module N is working end-to-end.
