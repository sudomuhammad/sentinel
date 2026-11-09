"""The proxy addon, driven with mitmproxy's own test flows."""

import asyncio
import importlib
import json

import pytest
from mitmproxy.test import tflow, tutils

from sentinel import audit, spend
from sentinel.canary import make_canaries
from sentinel.policy import Policy

CANARIES = make_canaries()
CLAUDE_CALL = json.dumps({"model": "claude-opus-5-5", "max_tokens": 10}).encode()
OPENAI_CALL = json.dumps({"model": "gpt-6-luna", "input": "hi"}).encode()


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
    flow = send(addon, "POST", "api.anthropic.com", "/v1/messages", CLAUDE_CALL, sent_headers)
    assert flow.response is None  # forwarded
    assert flow.request.headers["x-api-key"] == "sk-real-key"
    assert "authorization" not in flow.request.headers


@pytest.mark.parametrize("addon", ["openai"], indirect=True)
def test_openai_gets_a_bearer_token_and_anthropic_is_closed(addon):
    placeholder = [("authorization", "Bearer sentinel-placeholder")]
    flow = send(addon, "POST", "api.openai.com", "/v1/responses", OPENAI_CALL, placeholder)
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


def respond(flow, body, content_type="application/json"):
    flow.response = tutils.tresp(
        content=body.encode(), headers=[(b"content-type", content_type.encode())]
    )
    flow.response.status_code = 200
    return flow


def test_model_without_a_price_is_refused(addon):
    unpriced = json.dumps({"model": "claude-unlisted-9"}).encode()
    flow = send(addon, "POST", "api.anthropic.com", "/v1/messages", unpriced)
    assert flow.response.status_code == 403
    assert "no price" in audit.read(addon.audit_log)[-1]["reason"]


def test_spend_cap_halts_the_run(addon):
    addon.policy = addon.policy.__class__.from_dict(
        {**addon.policy.raw, "budget": {**addon.policy.raw["budget"], "max_budget_usd": 0.01}}
    )
    flow = send(addon, "POST", "api.anthropic.com", "/v1/messages", CLAUDE_CALL)
    stream = (
        'event: message_start\ndata: {"type":"message_start","message":{"usage":'
        '{"input_tokens":2000,"output_tokens":1}}}\n\n'
        'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":500}}\n\n'
    )
    addon.response(respond(flow, stream, "text/event-stream"))
    assert addon.spent_usd == spend.cost((4.0, 20.0), 2000, 500)  # $0.018
    assert addon.halted.startswith("spend cap")
    assert (
        send(addon, "POST", "api.anthropic.com", "/v1/messages", CLAUDE_CALL).response.status_code
        == 403
    )


@pytest.mark.parametrize("addon", ["openai"], indirect=True)
def test_openai_usage_is_counted(addon):
    flow = send(addon, "POST", "api.openai.com", "/v1/responses", OPENAI_CALL)
    addon.response(
        respond(flow, json.dumps({"usage": {"input_tokens": 1000, "output_tokens": 100}}))
    )
    assert addon.spent_usd == spend.cost((0.10, 0.50), 1000, 100)
    assert not addon.halted


def test_package_allowlists(addon):
    addon.policy = addon.policy.__class__.from_dict(
        {**addon.policy.raw, "packages": {**addon.policy.raw["packages"],
                                          "npm_allow": ["left-pad"], "pypi_allow": ["Requests"]}}
    )  # fmt: skip
    assert send(addon, "GET", "registry.npmjs.org", "/left-pad").response is None
    assert send(addon, "GET", "registry.npmjs.org", "/lodahs").response.status_code == 403
    assert send(addon, "GET", "pypi.org", "/simple/requests/").response is None
    assert send(addon, "GET", "pypi.org", "/simple/reqeusts/").response.status_code == 403


def test_pypi_index_asks_for_dates_and_hides_fresh_files(addon):
    flow = send(addon, "GET", "pypi.org", "/simple/demo/")
    assert flow.request.headers["accept"].startswith("application/vnd.pypi.simple.v1+json")
    index = {"name": "demo", "files": [
        {"filename": "demo-1.0.tar.gz", "upload-time": "2020-01-01T00:00:00Z"},
        {"filename": "demo-9.0.tar.gz", "upload-time": "2999-01-01T00:00:00Z"},
    ]}  # fmt: skip
    addon.response(respond(flow, json.dumps(index), "application/vnd.pypi.simple.v1+json"))
    shown = [f["filename"] for f in json.loads(flow.response.get_text())["files"]]
    assert shown == ["demo-1.0.tar.gz"]
    assert (
        send(addon, "GET", "files.pythonhosted.org", "/packages/a/b/demo-1.0.tar.gz").response
        is None
    )
    fresh = send(addon, "GET", "files.pythonhosted.org", "/packages/a/b/demo-9.0.tar.gz")
    assert fresh.response.status_code == 403
