# ADR 004: Kyverno for admission control

## Status
Accepted

## Context
Need policy-as-code admission control to reject non-compliant workloads before
they run. Policies must be testable in CI before cluster apply.

## Decision
Use Kyverno for admission control policies.

## Rationale
- K8s-native YAML syntax — policies look like K8s resources, no new language to learn
- Supports validate, mutate, and generate policy types
- kyverno CLI enables policy unit testing in GitHub Actions without a live cluster
- CNCF incubating project, active development
- Faster to write correct policies than OPA/Rego for this use case

## Rejected Alternatives
- OPA/Gatekeeper: Rego is a purpose-built policy language, more widely referenced
  on job descriptions, but significantly higher learning curve. Considered for future
  addition as a stretch goal to demonstrate Rego knowledge.
- Pod Security Admission (built-in): Too coarse-grained, only three levels
  (privileged/baseline/restricted), no custom rules

## Consequences
Policies stored in security/kyverno/ and tested via kyverno CLI in CI pipeline.
Kyverno webhook must be running before any workload deployments or all deployments
will be blocked.
