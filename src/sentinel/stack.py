"""One Docker Compose project per run: proxy, attacker stand-in and the agent sandbox."""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from sentinel import audit

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "compose.yaml"


class Stack:
    def __init__(self, run_id: str, run_dir: Path, secrets: dict[str, str]):
        self.project = f"sentinel-{run_id}"
        self.agent_name = f"{self.project}-agent"
        # Values reach containers by name (`-e NAME`) so they never appear in argv.
        self.env = {
            **os.environ,
            **secrets,
            "RUN_DIR": str(run_dir),
            "SANDBOX_UID": str(os.getuid()),
            "SANDBOX_GID": str(os.getgid()),
        }
        self.secret_names = sorted(secrets)
        self.proxy_log = run_dir / "audit" / "proxy.jsonl"
        self.base = ["docker", "compose", "-p", self.project, "-f", str(COMPOSE_FILE)]

    def compose(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run([*self.base, *args], env=self.env, check=check, capture_output=True)

    def __enter__(self) -> Stack:
        self.compose("up", "--detach", "--wait", "--quiet-pull", "proxy", "attacker")
        try:
            self._wait_for_policy()
        except BaseException:
            self.__exit__()
            raise
        return self

    def _wait_for_policy(self, timeout: float = 20) -> None:
        """mitmproxy runs as an open proxy if our addon fails to load. Refuse to go on."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(e["event"] == "ready" for e in audit.read(self.proxy_log)):
                return
            time.sleep(0.25)
        logs = self.compose("logs", "proxy", check=False).stdout.decode()[-2000:]
        raise RuntimeError(f"egress proxy did not load its policy:\n{logs}")

    def __exit__(self, *exc) -> None:
        self.compose("down", "--volumes", "--remove-orphans", "--timeout", "2")

    def run_sandbox(
        self,
        service: str,
        command: list[str],
        log: Path,
        timeout: int,
        should_stop: Callable[[], str | None],
    ) -> tuple[int | None, str | None]:
        """Run the sandbox to completion. Returns (exit code, reason it was stopped early)."""
        cmd = [*self.base, "run", "--rm", "--no-deps", "--name", self.agent_name, "-T"]
        for name in self.secret_names:
            cmd += ["-e", name]
        cmd += [service, *command]

        deadline = time.monotonic() + timeout
        with log.open("wb") as out:
            proc = subprocess.Popen(cmd, env=self.env, stdout=out, stderr=subprocess.STDOUT)
            stopped = None
            while proc.poll() is None:
                stopped = should_stop() or (
                    f"time budget of {timeout}s used up" if time.monotonic() > deadline else None
                )
                if stopped:
                    subprocess.run(["docker", "kill", self.agent_name], capture_output=True)
                    proc.wait()
                    break
                time.sleep(0.5)
        return proc.returncode, stopped

    def build(self) -> None:
        self.compose("build", "--quiet", "sandbox")
