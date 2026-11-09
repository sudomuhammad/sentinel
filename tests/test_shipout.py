import os

import pytest

from sentinel import shipout
from sentinel.canary import make_canaries
from sentinel.gitops import IDENTITY, git
from sentinel.policy import Policy

POLICY = Policy.load()


@pytest.fixture
def repos(tmp_path, monkeypatch):
    """A clean clone and the agent's workspace clone of the same one-commit repo."""
    monkeypatch.setattr(shipout, "gitleaks", lambda *a: [])  # needs Docker; covered by evals
    origin = tmp_path / "origin"
    (origin / "src").mkdir(parents=True)
    (origin / "src" / "app.js").write_text("module.exports = 1;\n")
    (origin / "old.txt").write_text("remove me\n")
    git(origin, "init", "--quiet", "--initial-branch=main")
    git(origin, "add", "--all")
    git(origin, *IDENTITY, "commit", "--quiet", "-m", "init")
    clean, workspace = tmp_path / "clean", tmp_path / "workspace"
    git(None, "clone", "--quiet", str(origin), str(clean))
    git(None, "clone", "--quiet", str(origin), str(workspace))
    return clean, workspace, tmp_path / "scan"


def gate(clean, workspace, scratch, canaries=()):
    files = shipout.stage(workspace, clean)
    return shipout.check(clean, files, POLICY, list(canaries), scratch)


def test_ordinary_change_is_accepted(repos):
    clean, workspace, scratch = repos
    (workspace / "src" / "app.js").write_text("module.exports = 2;\n")
    (workspace / "old.txt").unlink()
    result = gate(clean, workspace, scratch)
    assert result.accepted
    assert sorted(result.files) == ["old.txt", "src/app.js"]


def test_no_change_is_not_shipped(repos):
    result = gate(*repos)
    assert not result.accepted
    assert result.violations == []


def test_workflow_change_is_rejected(repos):
    clean, workspace, scratch = repos
    (workspace / ".github" / "workflows").mkdir(parents=True)
    (workspace / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    result = gate(clean, workspace, scratch)
    assert not result.accepted
    assert "protected path" in result.violations[0]


def test_symlink_is_rejected(repos):
    clean, workspace, scratch = repos
    os.symlink(os.path.expanduser("~/.ssh/id_rsa"), workspace / "key")
    result = gate(clean, workspace, scratch)
    assert any("adds a symlink" in v for v in result.violations)


def test_canary_in_diff_is_rejected(repos):
    clean, workspace, scratch = repos
    canaries = make_canaries()
    (workspace / "debug.js").write_text(f"const k = '{canaries['GITHUB_TOKEN']}';\n")
    result = gate(clean, workspace, scratch, canaries.values())
    assert any("canary" in v for v in result.violations)


def test_agent_git_hooks_never_run_or_ship(repos):
    clean, workspace, scratch = repos
    hook = workspace / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\ntouch escaped\n")
    hook.chmod(0o755)
    git(workspace, "config", "core.fsmonitor", "touch escaped-fsmonitor; false")
    (workspace / "src" / "app.js").write_text("module.exports = 3;\n")

    result = gate(clean, workspace, scratch)
    shipout.commit(clean, "agent/test", "agent: test")

    assert result.accepted
    assert not (clean / ".git" / "hooks" / "pre-commit").exists()
    for root in (clean, workspace):
        assert not (root / "escaped").exists()
        assert not (root / "escaped-fsmonitor").exists()
