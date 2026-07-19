# Demo evidence artifacts

`sample-portable-proof.{json,md}` is a committed, sanitized example from the deterministic
cluster-free demo. It proves the shape of the evidence judges receive without claiming
that replayed or simulated records are live cluster observations.

Running `make demo-platform` writes timestamped evidence here and refreshes
`latest-demo.{json,md}`. Running `make demo-platform-live` writes the separately labeled
live-k3s proof. Generated runs remain ignored because their timestamps and measurements
change on every execution; the committed sample remains stable for GitHub reviewers.

| Artifact | Provenance | Kubernetes mutation | Availability claim |
|---|---|---:|---|
| `sample-portable-proof.*` | replayed Argus + Phoenix simulator | None | Not measured |
| generated `latest-live-demo.*` | observed Argus + live Chaos Mesh | Isolated approved namespace | Measured |

Generate fresh evidence by following [`setup.md`](../../setup.md).
