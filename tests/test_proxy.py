"""The proxy addon, driven with mitmproxy's own test flows."""

import asyncio
import importlib
import json

import pytest
from mitmproxy.test import tflow, tutils

from sentinel import audit
from sentinel.canary import make_canaries
from sentinel.policy import Policy

CANARIES = make_canaries()


@pytest.fixture(params=["anthropic"])
def addon(request, tmp_path, monkeypatch):
    policy = Policy.load().with_provider(request.param)
    config = tmp_path / "run.json"
    config.write_text(json.dumps({"policy": policy.raw, "canaries": CANARIES}))
    monkeypatch.setenv("SENTINEL_RUN_CONFIG", str(config))
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "proxy.jsonl"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-key")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-key")
    module = importlib.import_module("sentinel.proxy_addon")
    return importlib.reload(module).addons[0]


def send(addon, method="GET", host="attacker", path="/", content=b"", headers=()):
    req = tutils.treq(method=method.encode(), host=host, port=443, scheme=b"https",
                      path=path.encode(), content=content)  # fmt: skip
    for key, value in headers:
        req.headers[key] = value
    flow = tflow.tflow(req=req)
    asyncio.run(addon.request(flow))
    return flow


def events(addon):
    return [e["event"] for e in audit.read(addon.audit_log)]


def test_unknown_host_is_blocked_and_logged(addon):
    flow = send(addon, host="attacker", path="/collect")
    assert flow.response.status_code == 403
    assert events(addon) == ["deny"]


def test_model_api_gets_the_real_key_and_loses_any_other(addon):
    sent_headers = [("x-api-key", "sentinel-placeholder"), ("authorization", "Bearer x")]
    flow = send(addon, "POST", "api.anthropic.com", "/v1/messages", headers=sent_headers)
    assert flow.response is None  # forwarded
    assert flow.request.headers["x-api-key"] == "sk-real-key"
    assert "authorization" not in flow.request.headers


@pytest.mark.parametrize("addon", ["openai"], indirect=True)
def test_openai_gets_a_bearer_token_and_anthropic_is_closed(addon):
    flow = send(addon, "POST", "api.openai.com", "/v1/responses",
                headers=[("authorization", "Bearer sentinel-placeholder")])  # fmt: skip
    assert flow.response is None
    assert flow.request.headers["authorization"] == "Bearer sk-openai-key"
    assert send(addon, "POST", "api.anthropic.com", "/v1/messages").response.status_code == 403


def test_canary_halts_the_run_and_blocks_everything_after(addon):
    leak = f"AWS_ACCESS_KEY_ID={CANARIES['AWS_ACCESS_KEY_ID']}".encode()
    first = send(addon, "GET", "registry.npmjs.org", "/left-pad", content=leak)
    later = send(addon, "POST", "api.anthropic.com", "/v1/messages")
    assert first.response.status_code == 403
    assert later.response.status_code == 403
    assert events(addon)[:2] == ["halt", "deny"]


def test_canary_in_url_is_caught_even_on_the_model_api(addon):
    flow = send(addon, "GET", "api.anthropic.com", f"/v1/models?k={CANARIES['GITHUB_TOKEN']}")
    assert flow.response.status_code == 403
    assert addon.halted


def test_hook_errors_fail_closed(addon, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("bug in policy code")

    monkeypatch.setattr(addon.policy.__class__, "check_request", boom)
    flow = send(addon, "POST", "api.anthropic.com", "/v1/messages")
    assert flow.response.status_code == 403
    assert addon.halted.startswith("proxy error")
    assert "error" in events(addon)


def test_connect_to_unknown_host_is_refused(addon):
    flow = tflow.tflow(req=tutils.treq(method=b"CONNECT", host="attacker", port=443, path=b""))
    addon.http_connect(flow)
    assert flow.response.status_code == 403
