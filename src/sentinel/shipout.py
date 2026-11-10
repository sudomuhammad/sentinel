"""Ship-out gate: the only way the agent's work leaves the run.

The agent never commits or pushes. After it finishes, the orchestrator copies its working tree
into a clean clone (never touching the agent's .git), checks the change, and only then
commits it to an agent/* branch.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.canary import find_canaries
from sentinel.gitops import IDENTITY, git, mirror_tree
from sentinel.policy import Policy

GITLEAKS_IMAGE = "zricethezav/gitleaks:v8.30.1"
LINK_MODES = {"120000": "symlink", "160000": "submodule"}
CHECKS = (  # what check() covers, for people reading a pull request
    "file count",
    "protected paths",
    "dependency files",
    "symlinks and submodules",
    "canary credentials",
    "gitleaks",
)


@dataclass
class GateResult:
    files: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return bool(self.files) and not self.violations


def stage(workspace: Path, clean: Path) -> list[str]:
    """Copy the agent's working tree over the clean clone and stage it. Returns changed paths."""
    mirror_tree(workspace, clean)
    git(clean, "add", "--all")
    return _nul_split(git(clean, "diff", "--cached", "--name-only", "--no-renames", "-z"))


def _nul_split(output: str) -> list[str]:
    """Split `git -z` output. Without -z, git quotes unusual names and patterns stop matching."""
    return [item for item in output.split("\0") if item]


def check(
    clean: Path, files: list[str], policy: Policy, canaries: list[str], scratch: Path
) -> GateResult:
    violations = []
    if len(files) > policy.max_changed_files:
        violations.append(f"{len(files)} files changed, limit is {policy.max_changed_files}")
    for path in files:
        if pattern := policy.denied_path(path):
            violations.append(f"{path}: protected path ({pattern})")
        elif policy.is_dependency_file(path) and not policy.allow_dependency_changes:
            violations.append(f"{path}: dependency change needs a person to review it")

    raw = _nul_split(git(clean, "diff", "--cached", "--raw", "--no-renames", "-z"))
    for meta, path in zip(raw[::2], raw[1::2], strict=True):  # ":old new sha sha status", path
        if kind := LINK_MODES.get(meta.split()[1]):
            violations.append(f"{path}: adds a {kind}")

    diff = git(clean, "diff", "--cached", "--text", "--no-ext-diff")
    if hits := find_canaries(diff.encode(), canaries):
        violations.append(f"diff contains {len(hits)} canary credential(s)")

    violations += gitleaks(clean, files, scratch)
    return GateResult(files=files, violations=violations)


def gitleaks(clean: Path, files: list[str], scratch: Path) -> list[str]:
    """Scan the changed files (and nothing else) with gitleaks in a throwaway container."""
    scan, out = scratch / "files", scratch / "out"
    for path in files:
        source = clean / path
        if source.is_file() and not source.is_symlink():
            (scan / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, scan / path)
    if not scan.exists():
        return []
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o777)
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--network=none",
            "-v", f"{scan}:/scan:ro", "-v", f"{out}:/out",
            GITLEAKS_IMAGE, "dir", "/scan",
            "--no-banner", "--redact", "--exit-code=0", "--log-level=error",
            "--report-format=json", "--report-path=/out/report.json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    report = out / "report.json"
    if result.returncode != 0 or not report.exists():
        return [f"secret scan failed to run: {result.stderr.strip()[:200]}"]  # fail closed
    findings = json.loads(report.read_text() or "[]")
    return [
        f"{f['File'].removeprefix('/scan/')}:{f['StartLine']}: secret detected ({f['RuleID']})"
        for f in findings
    ]


def commit(clean: Path, branch: str, message: str) -> str:
    git(clean, "switch", "--quiet", "--create", branch)
    git(clean, *IDENTITY, "commit", "--quiet", "--message", message)
    return git(clean, "rev-parse", "HEAD").strip()
