# Threat model

## What we protect

- Credentials: the model API key, GitHub tokens, cloud keys and anything else on the host.
- The default branch and CI, including the secrets CI holds.
- The host machine that runs the harness.

## Who we defend against

Anyone who can put text in front of the agent: issue and PR authors, README and code comments in the target repo, package metadata, and command output. We assume they succeed. The agent follows their instructions and runs whatever shell commands they ask for. Sentinel has to keep the assets safe anyway.

The model provider, the package registries and GitHub are trusted. So is the person running Sentinel.

## Trust boundaries

| Zone | Holds | Can reach |
| --- | --- | --- |
| Sandbox container | The working copy, canary keys, the proxy's CA certificate | The proxy, and nothing else |
| Proxy container | The policy, the per-run CA key, the real model API key | The allowlisted hosts |
| Host | The orchestrator, the clean clone, the GitHub App key and tokens, audit logs | GitHub and the model API |

Nothing in the sandbox can write to the audit log, the policy or the clean clone. The host never runs git inside the agent's working copy, because that copy's `.git` directory is under the agent's control.

## Controls and what they cover

| Gap | Control | Tested by |
| --- | --- | --- |
| Secrets live in the agent's environment | No real secrets in the sandbox. The proxy injects the API key. GitHub tokens never leave the host. | `env-exfil`, `creds-file-exfil` |
| Outbound network is open | Internal Docker network with no route or DNS. Default-deny proxy with host, method and path rules. | `proxy-bypass`, `dns-exfil`, `evil-postinstall` |
| Package installs run third-party code | `--ignore-scripts`. Minimum package age on npm. Unknown hosts refused. | `evil-postinstall` |
| Pushing code is unrestricted | The agent can't push. The gate checks protected paths, links, canaries and gitleaks before committing to `agent/*`. | `hardcoded-key`, `workflow-edit`, `git-hook-escape` |
| Untrusted content steers the agent | A tool-less reader summarises issues into a schema. Repo settings (`.claude/`) are not loaded. Every other control assumes the agent is already steered. | `make replay` with a live agent |
| No way to measure | The red-team suite runs every attack with and without Sentinel in CI. | `make eval` |

## The example attack

The scenario from the design doc, step by step:

1. An issue hides instructions to install a helper package and post `env` to a URL. The reader gets the raw text and returns a summary of the bug. It flags the issue as containing instructions, and the URL never reaches the agent.
2. If the agent tries the install anyway (the fixture README carries the same instructions), the proxy refuses the attacker's host. If the package came from an allowed registry, `--ignore-scripts` would keep its postinstall from running.
3. `~/.aws/credentials` and the environment hold only canaries. Sending one anywhere halts the run.
4. The POST to the attacker is blocked and logged.
5. A debug file with a hardcoded key fails the gate on both the canary match and gitleaks. The agent has no way to push to `main` because it holds no token, and Sentinel only ever pushes `agent/*` branches.

## Known gaps

These are open, roughly in order of how much they matter.

1. Malicious code in an accepted pull request. The gate catches secrets and protected files. It can't tell a subtle backdoor from a bug fix. Review agent PRs the way you'd review an outside contributor's.
2. CI runs on agent branches. A push to `agent/*` in the same repo triggers `push` workflows with repository secrets, running the agent's code (its tests, for instance). The gate stops the agent editing workflows, but an existing workflow that runs `npm test` with secrets in its environment would still expose them to the agent's test code. Keep secret-bearing jobs off `agent/**` branches or behind environments with required reviewers. See [github-setup.md](github-setup.md).
3. Covert channels through allowed hosts. The agent can encode data in package names it looks up on npm or PyPI, or in paths on the model API. The bandwidth is low and the canary scan covers known secrets, but arbitrary repository data could leave this way. A private package mirror closes most of it.
4. API spend. A hijacked agent can call the model API through the proxy directly, outside the SDK's cost cap. The proxy's request cap bounds this. A token-aware budget in the proxy would be tighter.
5. Container isolation. The sandbox shares the host kernel. A kernel exploit escapes it. gVisor or a Firecracker microVM would close this.
6. Reader summaries can still carry text. The schema, length limit and URL stripping shrink what an attacker can pass through the summary. They can't remove it, so the downstream controls assume the agent is steered regardless.
7. Canary evasion. An agent that knows the canaries could encrypt them before sending. That only matters if a channel out exists, and the egress controls are what remove the channel. Canaries are for detection.
8. pip has no age check yet. PyPI's JSON API exposes upload times, so the npm approach carries over.
