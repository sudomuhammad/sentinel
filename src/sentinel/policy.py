"""Policy model shared by the orchestrator and the egress proxy.

Standard library only: the proxy container imports this module as-is.
"""

from __future__ import annotations

import copy
import fnmatch
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "policy.toml"
PROVIDERS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


@dataclass(frozen=True)
class EgressRule:
    host: str
    methods: tuple[str, ...] = ("GET", "HEAD")
    paths: tuple[str, ...] = ("/*",)
    inject_header: str | None = None
    inject_env: str | None = None
    inject_prefix: str = ""
    scan_body: bool = True

    def allows(self, method: str, path: str) -> bool:
        path = path.split("?", 1)[0]
        return method.upper() in self.methods and any(
            fnmatch.fnmatchcase(path, pattern) for pattern in self.paths
        )


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: EgressRule | None = None


@dataclass(frozen=True)
class Policy:
    raw: dict[str, Any]
    egress: tuple[EgressRule, ...]
    provider: str
    model: str
    reader_model: str
    max_turns: int
    max_budget_usd: float
    timeout_seconds: int
    max_requests: int
    npm_registry: str
    min_package_age_days: int
    branch_prefix: str
    max_changed_files: int
    deny_paths: tuple[str, ...]

    @classmethod
    def load(cls, path: Path = DEFAULT_POLICY) -> Policy:
        return cls.from_dict(tomllib.loads(Path(path).read_text()))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Policy:
        provider = raw["agent"]["provider"]
        if provider not in PROVIDERS:
            raise ValueError(f"unknown provider {provider!r}, expected one of {sorted(PROVIDERS)}")
        rules = tuple(
            EgressRule(
                host=r["host"].lower(),
                methods=tuple(m.upper() for m in r.get("methods", ("GET", "HEAD"))),
                paths=tuple(r.get("paths", ("/*",))),
                inject_header=r.get("inject", {}).get("header"),
                inject_env=r.get("inject", {}).get("env"),
                inject_prefix=r.get("inject", {}).get("prefix", ""),
                scan_body=r.get("scan_body", True),
            )
            for r in raw.get("egress", [])
            if r.get("provider") in (None, provider)  # only the active provider's API
        )
        models, budget = raw["agent"][provider], raw["budget"]
        packages, shipout = raw["packages"], raw["shipout"]
        return cls(
            raw=raw,
            egress=rules,
            provider=provider,
            model=models["model"],
            reader_model=models["reader_model"],
            max_turns=budget["max_turns"],
            max_budget_usd=budget["max_budget_usd"],
            timeout_seconds=budget["timeout_seconds"],
            max_requests=budget["max_requests"],
            npm_registry=packages["npm_registry"].lower(),
            min_package_age_days=packages["min_age_days"],
            branch_prefix=shipout["branch_prefix"],
            max_changed_files=shipout["max_changed_files"],
            deny_paths=tuple(shipout["deny_paths"]),
        )

    def with_provider(self, provider: str | None) -> Policy:
        if provider is None or provider == self.provider:
            return self
        raw = copy.deepcopy(self.raw)
        raw["agent"]["provider"] = provider
        return Policy.from_dict(raw)

    @property
    def api_key_env(self) -> str:
        return PROVIDERS[self.provider]

    def knows_host(self, host: str) -> bool:
        return any(rule.host == host.lower() for rule in self.egress)

    def check_request(self, method: str, host: str, path: str) -> Decision:
        rules = [rule for rule in self.egress if rule.host == host.lower()]
        if not rules:
            return Decision(False, f"host {host} is not on the allowlist")
        for rule in rules:
            if rule.allows(method, path):
                return Decision(True, "allowed", rule)
        return Decision(False, f"{method} {path.split('?', 1)[0]} is not allowed on {host}")

    def denied_path(self, path: str) -> str | None:
        """Return the deny pattern a changed file matches, if any."""
        return next((p for p in self.deny_paths if fnmatch.fnmatchcase(path, p)), None)
