"""mitmproxy addon: the only route out of the sandbox.

Enforces the egress allowlist, injects credentials the sandbox never holds, watches for
canary credentials, applies the package policy (minimum age and optional allowlists for npm
and PyPI), caps model spend and logs every request.
Runs inside the proxy container: `mitmdump -s /app/sentinel/proxy_addon.py`.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
import urllib.request
from pathlib import Path

from mitmproxy import http

from sentinel import audit, packages, spend
from sentinel.canary import find_canaries
from sentinel.policy import Policy

RUN_CONFIG = Path(os.environ.get("SENTINEL_RUN_CONFIG", "/etc/sentinel/run.json"))
AUDIT_LOG = Path(os.environ.get("SENTINEL_AUDIT_LOG", "/audit/proxy.jsonl"))
MODEL = "sentinel_model"  # flow.metadata key: the priced model of a model API call


def fail_closed(hook):
    """mitmproxy forwards a flow when a hook raises. Turn any error into a block and a halt."""
    if inspect.iscoroutinefunction(hook):

        @functools.wraps(hook)
        async def guarded(self, flow):
            try:
                await hook(self, flow)
            except Exception as exc:
                self._fail(flow, exc)

    else:

        @functools.wraps(hook)
        def guarded(self, flow):
            try:
                hook(self, flow)
            except Exception as exc:
                self._fail(flow, exc)

    return guarded


class Sentinel:
    def __init__(self, run_config: Path = RUN_CONFIG, audit_log: Path = AUDIT_LOG) -> None:
        self.audit_log = audit_log
        config = json.loads(run_config.read_text())
        self.policy = Policy.from_dict(config["policy"])
        self.canaries: list[str] = list(config["canaries"].values())
        self.age_limit = packages.cutoff(self.policy.min_package_age_days)
        self.publish_times: dict[str, dict[str, str]] = {}  # npm name or PyPI project -> times
        self.requests = 0
        self.spent_usd = 0.0
        self.halted: str | None = None

    # Hooks -----------------------------------------------------------------

    def running(self) -> None:
        """The orchestrator waits for this event; without it the agent never starts."""
        audit.record(self.audit_log, "ready", rules=len(self.policy.egress))

    @fail_closed
    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Refuse tunnels to unknown hosts before any TLS is set up."""
        host = flow.request.host
        if self.halted or not self.policy.knows_host(host):
            self._deny(flow, self.halted or f"host {host} is not on the allowlist")

    @fail_closed
    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        self.requests += 1
        if self.halted:
            return self._deny(flow, f"run halted: {self.halted}")
        if self.requests > self.policy.max_requests:
            return self._halt(flow, f"request budget of {self.policy.max_requests} exceeded")

        decision = self.policy.check_request(req.method, req.host, req.path)
        scan_body = decision.rule.scan_body if decision.rule else True
        if hits := find_canaries(self._wire_bytes(req, scan_body), self.canaries):
            return self._halt(flow, f"canary credential sent to {req.host}", canaries=len(hits))
        if not decision.allowed:
            return self._deny(flow, decision.reason)

        rule = decision.rule
        if rule.provider and req.method == "POST" and (reason := self._price_check(flow)):
            return self._deny(flow, reason)
        if rule.inject_header:
            secret = os.environ.get(rule.inject_env or "")
            if not secret:
                return self._deny(flow, f"no credential configured for {req.host}")
            req.headers.pop("authorization", None)
            req.headers[rule.inject_header] = rule.inject_prefix + secret
        if reason := await self._package_check(req):
            return self._deny(flow, reason)

        audit.record(self.audit_log, "allow", method=req.method, host=req.host, path=req.path[:300])

    @fail_closed
    def response(self, flow: http.HTTPFlow) -> None:
        if MODEL in flow.metadata:
            return self._record_spend(flow)
        req, resp = flow.request, flow.response
        if resp.status_code != 200 or "json" not in resp.headers.get("content-type", ""):
            return
        if req.host == self.policy.npm_registry and packages.npm_packument_name(req.path):
            doc = json.loads(resp.get_text() or "")
            self.publish_times[doc.get("name", "")] = doc.get("time", {})
            resp.set_text(json.dumps(packages.filter_packument(doc, self.age_limit)))
        elif req.host == self.policy.pypi_index and (
            project := packages.pypi_index_project(req.path)
        ):
            index = json.loads(resp.get_text() or "")
            self.publish_times[project] = packages.upload_times(index)
            resp.set_text(json.dumps(packages.filter_simple_index(index, self.age_limit)))

    # Spend -----------------------------------------------------------------

    def _price_check(self, flow: http.HTTPFlow) -> str | None:
        """Model calls must name a model with a known price, so every one can be counted."""
        try:
            model = json.loads(flow.request.get_text() or "{}").get("model")
        except ValueError:
            model = None
        if not isinstance(model, str) or spend.price_for(model, self.policy.pricing) is None:
            return f"no price for model {model!r} in policy.toml [pricing]"
        flow.metadata[MODEL] = model
        return None

    def _record_spend(self, flow: http.HTTPFlow) -> None:
        model = flow.metadata[MODEL]
        input_tokens, output_tokens = spend.tokens(flow.response.get_text() or "")
        price = spend.price_for(model, self.policy.pricing)
        self.spent_usd += spend.cost(price, input_tokens, output_tokens)
        audit.record(
            self.audit_log, "spend", model=model, input_tokens=input_tokens,
            output_tokens=output_tokens, total_usd=round(self.spent_usd, 6),
        )  # fmt: skip
        if self.spent_usd > self.policy.max_budget_usd and not self.halted:
            self.halted = f"spend cap of ${self.policy.max_budget_usd} reached"
            audit.record(self.audit_log, "halt", host=flow.request.host, reason=self.halted)

    # Packages --------------------------------------------------------------

    async def _package_check(self, req: http.Request) -> str | None:
        """Reason to refuse a registry request, or None. Also asks for metadata with dates."""
        p, host = self.policy, req.host
        if host == p.npm_registry and (name := packages.npm_packument_name(req.path)):
            req.headers["accept"] = "application/json"  # abbreviated metadata has no dates
            return self._not_allowed(name, p.npm_allow)
        if host == p.npm_registry and (coords := packages.tarball_coordinates(req.path)):
            name, version = coords
            return self._not_allowed(name, p.npm_allow) or await self._too_new(
                name, version, f"https://{p.npm_registry}/{name.replace('/', '%2F')}",
                lambda doc: doc.get("time", {}), "application/json",
            )  # fmt: skip
        if host == p.pypi_index and (project := packages.pypi_index_project(req.path)):
            req.headers["accept"] = packages.PYPI_JSON  # the JSON index carries upload times
            return self._not_allowed(project, p.pypi_allow)
        if host == p.pypi_files and (file := packages.pypi_file_project(req.path)):
            project, filename = file
            return self._not_allowed(project, p.pypi_allow) or await self._too_new(
                project, filename, f"https://{p.pypi_index}/simple/{project}/",
                packages.upload_times, packages.PYPI_JSON,
            )  # fmt: skip
        if host == p.pypi_files:
            return f"unrecognised file name {req.path.rsplit('/', 1)[-1]!r}"
        return None

    @staticmethod
    def _not_allowed(name: str, allowlist: tuple[str, ...]) -> str | None:
        return None if packages.allowed(name, allowlist) else f"{name} is not on the allowlist"

    async def _too_new(self, name, key, url, extract, accept) -> str | None:
        if name not in self.publish_times:
            self.publish_times[name] = await asyncio.to_thread(self._fetch, url, extract, accept)
        if packages.old_enough(self.publish_times[name].get(key), self.age_limit):
            return None
        return f"{name} {key} is newer than {self.policy.min_package_age_days} days"

    @staticmethod
    def _fetch(url: str, extract, accept: str) -> dict[str, str]:
        """Publish times from the registry. Empty on failure, which fails the age check closed."""
        request = urllib.request.Request(url, headers={"accept": accept})  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:  # noqa: S310 - fixed hosts
                return extract(json.load(resp))
        except (OSError, ValueError):
            return {}

    # Helpers ---------------------------------------------------------------

    @staticmethod
    def _wire_bytes(req: http.Request, include_body: bool) -> bytes:
        head = (req.url + "\n" + "\n".join(f"{k}: {v}" for k, v in req.headers.items())).encode()
        body = (req.get_content(strict=False) or b"") if include_body else b""
        return head + body

    def _deny(self, flow: http.HTTPFlow, reason: str) -> None:
        req = flow.request
        audit.record(
            self.audit_log,
            "deny",
            method=req.method,
            host=req.host,
            path=req.path[:300],
            reason=reason,
        )
        flow.response = http.Response.make(
            403, f"Blocked by Sentinel: {reason}\n", {"content-type": "text/plain"}
        )

    def _fail(self, flow: http.HTTPFlow, exc: Exception) -> None:
        self.halted = self.halted or f"proxy error ({type(exc).__name__})"
        flow.response = http.Response.make(
            403, b"Blocked by Sentinel: proxy error\n", {"content-type": "text/plain"}
        )
        audit.record(self.audit_log, "error", host=flow.request.host, error=repr(exc)[:300])

    def _halt(self, flow: http.HTTPFlow, reason: str, **fields) -> None:
        self.halted = reason
        audit.record(self.audit_log, "halt", host=flow.request.host, reason=reason, **fields)
        self._deny(flow, f"run halted: {reason}")


addons = [Sentinel()]
