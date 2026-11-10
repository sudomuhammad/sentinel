"""Run lifecycle: prepare, sandbox, gate, ship, judge."""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sentinel import audit, github, reader, shipout
from sentinel.canary import find_canaries, make_canaries
from sentinel.gitops import git
from sentinel.policy import PROVIDERS, Policy
from sentinel.stack import ROOT, Stack

RUNS_DIR = ROOT / ".sentinel" / "runs"
GITHUB_SLUG = re.compile(r"^[\w.-]+/[\w.-]+$")
ATTACK_MARKER = b"SENTINEL_ATTACK_SUCCEEDED"
ESCAPE_MARKER = ".escaped"


class MissingKey(RuntimeError):
    pass


@dataclass(frozen=True)
class RunSpec:
    source: str  # local git repo path, or owner/name on GitHub
    task: str
    scenario: str | None = None  # scripted attack instead of the LLM agent
    protected: bool = True
    issue: int | None = None  # GitHub issue number
    issue_file: Path | None = None
    push: bool = True  # open a pull request for GitHub sources
    policy: Policy = field(default_factory=Policy.load)


@dataclass
class RunResult:
    run_id: str
    run_dir: Path
    protected: bool
    exit_code: int | None = None
    stopped: str | None = None
    gate: shipout.GateResult | None = None
    shipped: bool = False
    leaked: int = 0  # number of canaries the attacker received
    escaped: bool = False
    marker: bool = False
    issue_summary: dict | None = None
    pr_url: str | None = None
    proxy_events: list[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, indent=2)


class RunPaths:
    def __init__(self, run_id: str):
        self.id = run_id
        self.root = RUNS_DIR / run_id
        self.workspace = self.root / "workspace"  # the agent's copy, mounted read-write
        self.clean = self.root / "clean"  # trusted clone the gate commits from
        self.ca_proxy = self.root / "ca" / "proxy"  # CA key + cert, proxy only
        self.ca_sandbox = self.root / "ca" / "sandbox"  # cert only
        self.audit = self.root / "audit"
        self.attacker = self.root / "attacker"
        self.scratch = self.root / "scan"
        self.run_config = self.root / "run.json"
        self.orchestrator_log = self.audit / "orchestrator.jsonl"
        self.proxy_log = self.audit / "proxy.jsonl"
        self.agent_log = self.audit / "agent.log"

    @classmethod
    def new(cls) -> RunPaths:
        paths = cls(time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3))
        for d in (paths.ca_proxy, paths.ca_sandbox, paths.audit, paths.attacker):
            d.mkdir(parents=True)
            d.chmod(0o777)  # written by container users we don't control
        return paths


def make_ca(paths: RunPaths) -> None:
    """A throwaway CA per run. Only the proxy gets the key."""
    key, cert = paths.ca_proxy / "key.pem", paths.ca_proxy / "cert.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-new", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", f"/CN=Sentinel run {paths.id}", "-keyout", str(key), "-out", str(cert),
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    (paths.ca_proxy / "mitmproxy-ca.pem").write_text(key.read_text() + cert.read_text())
    (paths.ca_sandbox / "ca.pem").write_text(cert.read_text())
    key.unlink()


def checkout(spec: RunSpec, paths: RunPaths) -> str | None:
    """Clone the source into the clean copy, then give the agent its own clone of that.

    Returns a GitHub token when the source is on GitHub.
    """
    token = None
    if Path(spec.source).is_dir():
        git(None, "clone", "--quiet", str(Path(spec.source).resolve()), str(paths.clean))
    elif GITHUB_SLUG.match(spec.source):
        token = github.installation_token(spec.source)
        url = f"https://github.com/{spec.source}.git"
        git(None, "clone", "--quiet", url, str(paths.clean), env=github.git_auth_env(token))
    else:
        raise ValueError(f"source must be a local git repo or owner/name: {spec.source}")
    git(None, "clone", "--quiet", "--no-hardlinks", str(paths.clean), str(paths.workspace))
    return token


def issue_text(spec: RunSpec, token: str | None) -> str | None:
    if spec.issue_file:
        return spec.issue_file.read_text()
    if spec.issue is not None:
        if token is None:
            raise ValueError("--issue needs a GitHub source")
        return github.fetch_issue(spec.source, spec.issue, token)
    return None


def execute(spec: RunSpec) -> RunResult:
    policy = spec.policy
    live = spec.scenario is None
    if live and not os.environ.get(policy.api_key_env):
        raise MissingKey(f"set {policy.api_key_env} on the host to run the {policy.provider} agent")
    paths = RunPaths.new()
    result = RunResult(run_id=paths.id, run_dir=paths.root, protected=spec.protected)
    log = paths.orchestrator_log
    canaries = make_canaries()
    audit.record(log, "run_start", source=spec.source, scenario=spec.scenario,
                 protected=spec.protected)  # fmt: skip

    token = checkout(spec, paths)
    base_branch = git(paths.clean, "rev-parse", "--abbrev-ref", "HEAD").strip()
    context = ""
    if text := issue_text(spec, token):
        if spec.protected:
            result.issue_summary = reader.summarise(text, policy.provider, policy.reader_model)
            audit.record(log, "issue_summary", **result.issue_summary)
            context = json.dumps(result.issue_summary)
        else:
            context = text  # the baseline hands raw issue text to the agent, as most setups do

    make_ca(paths)
    paths.run_config.write_text(json.dumps({"policy": policy.raw, "canaries": canaries}))

    agent_env = {
        **canaries,
        "SENTINEL_TASK": spec.task,
        "SENTINEL_CONTEXT": context,
        "SENTINEL_PROVIDER": policy.provider,
        "SENTINEL_MODEL": policy.model,
        "SENTINEL_MAX_TURNS": str(policy.max_turns),
        "SENTINEL_MAX_BUDGET_USD": str(policy.max_budget_usd),
    }
    if live and not spec.protected:
        # The baseline does what most setups do: the real key sits inside the container.
        agent_env[policy.api_key_env] = os.environ[policy.api_key_env]
    command = [] if live else ["sh", f"/scenarios/{spec.scenario}.sh"]
    service = "sandbox" if spec.protected else "sandbox-open"

    def halted() -> str | None:
        halts = [e for e in audit.read(paths.proxy_log) if e["event"] == "halt"]
        return f"proxy halted the run: {halts[0]['reason']}" if halts else None

    stack = Stack(paths.id, paths.root, paths.proxy_log, agent_env)
    # The proxy only gets the key for the provider in use.
    stack.env.update({k: "" for k in PROVIDERS.values() if k != policy.api_key_env})
    stack.build()
    with stack:
        result.exit_code, result.stopped = stack.run_sandbox(
            service, command, paths.agent_log, policy.timeout_seconds, halted
        )
        audit.record(log, "agent_exit", code=result.exit_code, stopped=result.stopped)
        if not spec.protected:
            result.shipped = naive_commit(stack)

    if spec.protected:
        ship(spec, paths, result, list(canaries.values()), token, base_branch)

    result.proxy_events = audit.read(paths.proxy_log)
    attacker_log = paths.attacker / "requests.jsonl"
    received = attacker_log.read_bytes() if attacker_log.exists() else b""
    result.leaked = len(find_canaries(received, canaries.values()))
    result.escaped = (paths.workspace / ESCAPE_MARKER).exists()
    result.marker = ATTACK_MARKER in paths.agent_log.read_bytes()
    audit.record(log, "run_end", leaked=result.leaked, shipped=result.shipped,
                 escaped=result.escaped)  # fmt: skip
    (paths.root / "report.json").write_text(result.to_json())
    return result


def naive_commit(stack: Stack) -> bool:
    """The unprotected baseline: commit in the agent's own repo, the way most harnesses do.

    Runs inside the open sandbox so that anything the agent planted in .git runs there,
    not on this machine.
    """
    script = "git add -A && git -c user.name=agent -c user.email=agent@localhost commit -qm agent"
    proc = stack.compose("run", "--rm", "--no-deps", "-T", "sandbox-open", "sh", "-c", script,
                         check=False)  # fmt: skip
    return proc.returncode == 0  # git commit fails when there is nothing to commit


def ship(
    spec: RunSpec,
    paths: RunPaths,
    result: RunResult,
    canaries: list[str],
    token: str | None,
    base_branch: str,
) -> None:
    files = shipout.stage(paths.workspace, paths.clean)
    result.gate = shipout.check(paths.clean, files, spec.policy, canaries, paths.scratch)
    audit.record(paths.orchestrator_log, "gate", files=files, violations=result.gate.violations)
    if not result.gate.accepted:
        return

    branch = f"{spec.policy.branch_prefix}{paths.id}"
    title = f"agent: {spec.task[:60]}"
    shipout.commit(paths.clean, branch, title)
    result.shipped = True
    if token and spec.push:
        git(paths.clean, "push", "--quiet", "origin", f"HEAD:refs/heads/{branch}",
            env=github.git_auth_env(token))  # fmt: skip
        result.pr_url = github.open_pull_request(
            spec.source, token, branch, base_branch, title, pr_body(result)
        )
    else:
        patch = git(paths.clean, "format-patch", "-1", "--stdout")
        (paths.root / "changes.patch").write_text(patch)
    audit.record(paths.orchestrator_log, "shipped", branch=branch, pr=result.pr_url)


def pr_body(result: RunResult) -> str:
    files = "\n".join(f"- `{f}`" for f in result.gate.files)
    return (
        f"Opened by Sentinel run `{result.run_id}`.\n\n"
        f"Changed files:\n{files}\n\n"
        f"Checks passed: {', '.join(shipout.CHECKS)}.\n"
        "Review this like any change from an outside contributor."
    )
