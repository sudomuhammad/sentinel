"""mitmproxy addon: the only route out of the sandbox.

Enforces the egress allowlist, injects credentials the sandbox never holds, watches for
canary credentials, applies the npm minimum-age policy and logs every request.
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

from sentinel import audit, packages
from sentinel.canary import find_canaries
from sentinel.policy import Policy

RUN_CONFIG = Path(os.environ.get("SENTINEL_RUN_CONFIG", "/etc/sentinel/run.json"))
AUDIT_LOG = Path(os.environ.get("SENTINEL_AUDIT_LOG", "/audit/proxy.jsonl"))


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
        self.publish_times: dict[str, dict[str, str]] = {}
        self.requests = 0
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
        if rule.inject_header:
            secret = os.environ.get(rule.inject_env or "")
            if not secret:
                return self._deny(flow, f"no credential configured for {req.host}")
            req.headers.pop("authorization", None)
            req.headers[rule.inject_header] = rule.inject_prefix + secret

        if req.host == self.policy.npm_registry and (reason := await self._npm_check(req)):
            return self._deny(flow, reason)

        audit.record(self.audit_log, "allow", method=req.method, host=req.host, path=req.path[:300])

    @fail_closed
    def response(self, flow: http.HTTPFlow) -> None:
        req, resp = flow.request, flow.response
        if (
            req.host == self.policy.npm_registry
            and packages.is_packument(req.path)
            and resp.status_code == 200
            and "json" in resp.headers.get("content-type", "")
        ):
            try:
                doc = json.loads(resp.get_text() or "")
            except ValueError:
                return self._deny(flow, "unreadable package metadata")
            self.publish_times[doc.get("name", "")] = doc.get("time", {})
            resp.set_text(json.dumps(packages.filter_packument(doc, self.age_limit)))

    # Helpers ---------------------------------------------------------------

    @staticmethod
    def _wire_bytes(req: http.Request, include_body: bool) -> bytes:
        head = (req.url + "\n" + "\n".join(f"{k}: {v}" for k, v in req.headers.items())).encode()
        body = (req.get_content(strict=False) or b"") if include_body else b""
        return head + body

    async def _npm_check(self, req: http.Request) -> str | None:
        if packages.is_packument(req.path):
            req.headers["accept"] = "application/json"  # abbreviated metadata omits publish times
            return None
        coords = packages.tarball_coordinates(req.path)
        if coords is None:
            return None
        name, version = coords
        times = self.publish_times.get(name) or await asyncio.to_thread(self._fetch_times, name)
        if not packages.old_enough(times.get(version), self.age_limit):
            return f"{name}@{version} is newer than {self.policy.min_package_age_days} days"
        return None

    def _fetch_times(self, name: str) -> dict[str, str]:
        """Publish times for a package. Empty on failure, which fails the age check closed."""
        url = f"https://{self.policy.npm_registry}/{name.replace('/', '%2F')}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310 - fixed https host
                times = json.load(resp).get("time", {})
        except (OSError, ValueError):
            return {}
        self.publish_times[name] = times
        return times

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
