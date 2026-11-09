# Security policy

Sentinel is a security tool, so a way around one of its controls counts as a vulnerability. That includes reaching a host the policy doesn't allow, getting a real credential into the sandbox, shipping a change the gate should have refused, or running code on the host from inside the sandbox.

Please report these privately through GitHub's "Report a vulnerability" button on this repository rather than in a public issue. Include the steps, or better, a scenario script in the format of `evals/scenarios/`. A confirmed bypass becomes a new scenario so it stays fixed.

Known gaps are listed in [docs/threat-model.md](docs/threat-model.md#known-gaps). Reports that extend one of them in a practical way are still welcome.
