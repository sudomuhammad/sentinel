"""Git helpers for the host side. Never pointed at the agent's .git directory."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

# Belt and braces for repos we control: no hooks, no fsmonitor, no file:// transports.
SAFE_CONFIG = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.file.allow=user",
]  # fmt: skip

IDENTITY = ["-c", "user.name=Sentinel", "-c", "user.email=sentinel@localhost"]


def git(repo: Path | None, *args: str, env: dict[str, str] | None = None) -> str:
    cmd = ["git", *SAFE_CONFIG]
    if repo is not None:
        cmd += ["-C", str(repo)]
    result = subprocess.run(
        [*cmd, *args],
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {result.stderr.strip()}")
    return result.stdout


def mirror_tree(src: Path, dst: Path, skip: str = ".git") -> None:
    """Make dst's working tree match src, leaving any `skip` directory on either side alone.

    Symlinks are copied as links, never followed, so a link to a host file stays a link.
    """
    for path in sorted(dst.rglob("*"), reverse=True):  # children before parents
        rel = path.relative_to(dst)
        if skip in rel.parts or (src / rel).exists() or (src / rel).is_symlink():
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if skip in rel.parts:
            continue
        target = dst / rel
        if path.is_dir() and not path.is_symlink():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target, follow_symlinks=False)
