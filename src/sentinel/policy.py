"""Policy model shared by the orchestrator and the egress proxy.

Standard library only: the proxy container imports this module as-is.
"""

from __future__ import annotations

import copy
import fnmatch
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sentinel.packages import normalise

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
    provider: str | None = None  # set on model API rules; their responses are priced

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
    reviewer_model: str
    review_enabled: bool
    review_rounds: int
    max_turns: int
    max_budget_usd: float
    timeout_seconds: int
    max_requests: int
    pricing: dict[str, tuple[float, float]]
    npm_registry: str
    pypi_index: str
    pypi_files: str
    min_package_age_days: int
    npm_allow: tuple[str, ...]
    pypi_allow: tuple[str, ...]
    branch_prefix: str
    max_changed_files: int
    deny_paths: tuple[str, ...]
    allow_dependency_changes: bool
    dependency_files: tuple[str, ...]

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
                provider=r.get("provider"),
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
            reviewer_model=models["reviewer_model"],
            review_enabled=raw["review"]["enabled"],
            review_rounds=raw["review"]["max_rounds"],
            max_turns=budget["max_turns"],
            max_budget_usd=budget["max_budget_usd"],
            timeout_seconds=budget["timeout_seconds"],
            max_requests=budget["max_requests"],
            pricing={model: tuple(price) for model, price in raw["pricing"].items()},
            npm_registry=packages["npm_registry"].lower(),
            pypi_index=packages["pypi_index"].lower(),
            pypi_files=packages["pypi_files"].lower(),
            min_package_age_days=packages["min_age_days"],
            npm_allow=tuple(packages.get("npm_allow", ())),
            pypi_allow=tuple(normalise(n) for n in packages.get("pypi_allow", ())),
            branch_prefix=shipout["branch_prefix"],
            max_changed_files=shipout["max_changed_files"],
            deny_paths=tuple(shipout["deny_paths"]),
            allow_dependency_changes=shipout["allow_dependency_changes"],
            dependency_files=tuple(shipout["dependency_files"]),
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

    def is_dependency_file(self, path: str) -> bool:
        name = PurePosixPath(path).name
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in self.dependency_files)
