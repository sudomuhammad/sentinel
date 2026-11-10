from datetime import UTC, datetime

from sentinel import packages
from sentinel.canary import find_canaries, make_canaries
from sentinel.policy import Policy

POLICY = Policy.load()
ANTHROPIC = POLICY.with_provider("anthropic")
OPENAI = POLICY.with_provider("openai")


def test_unknown_host_is_denied():
    decision = POLICY.check_request("GET", "attacker.example", "/")
    assert not decision.allowed
    assert "not on the allowlist" in decision.reason


def test_method_and_path_are_enforced_per_host():
    assert ANTHROPIC.check_request("POST", "api.anthropic.com", "/v1/messages?beta=true").allowed
    assert not ANTHROPIC.check_request("DELETE", "api.anthropic.com", "/v1/messages").allowed
    assert not POLICY.check_request("PUT", "registry.npmjs.org", "/-/user/org.couchdb.user").allowed
    assert not POLICY.check_request("GET", "pypi.org", "/account/login/").allowed


def test_host_match_is_case_insensitive():
    assert POLICY.check_request("GET", "Registry.NPMjs.org", "/left-pad").allowed


def test_only_the_active_providers_api_is_reachable():
    openai = POLICY.with_provider("openai")
    claude = POLICY.with_provider("anthropic")
    assert openai.check_request("POST", "api.openai.com", "/v1/responses").allowed
    assert not openai.check_request("POST", "api.anthropic.com", "/v1/messages").allowed
    assert claude.check_request("POST", "api.anthropic.com", "/v1/messages").allowed
    assert not claude.check_request("POST", "api.openai.com", "/v1/responses").allowed
    assert openai.model != claude.model
    assert openai.api_key_env == "OPENAI_API_KEY"


def test_model_api_injects_credential_and_skips_body_scan():
    rule = ANTHROPIC.check_request("POST", "api.anthropic.com", "/v1/messages").rule
    assert rule.inject_header == "x-api-key"
    assert rule.inject_env == "ANTHROPIC_API_KEY"
    assert rule.scan_body is False
    rule = OPENAI.check_request("POST", "api.openai.com", "/v1/responses").rule
    assert (rule.inject_header, rule.inject_prefix) == ("authorization", "Bearer ")


def test_protected_paths():
    assert POLICY.denied_path(".github/workflows/ci.yml") == ".github/*"
    assert POLICY.denied_path("docs/CODEOWNERS") == "*/CODEOWNERS"
    assert POLICY.denied_path(".claude/settings.json") == ".claude/*"
    assert POLICY.denied_path("src/github.py") is None


def test_canaries_found_in_plain_and_encoded_forms():
    import base64
    from urllib.parse import quote

    key = make_canaries()["AWS_ACCESS_KEY_ID"]
    wrappers = [
        f"key={key}".encode(),
        key.lower().encode() + b".example.com",
        key.encode().hex().encode(),
        quote(f"k={key}&x=1").encode(),
    ]
    # base64 at every alignment inside a larger blob
    wrappers += [base64.b64encode(prefix + key.encode() + b"tail") for prefix in (b"", b"a", b"ab")]
    for data in wrappers:
        assert find_canaries(data, [key]) == [key], data


def test_canaries_do_not_match_unrelated_data():
    canaries = make_canaries().values()
    assert find_canaries(b"AKIAIOSFODNN7EXAMPLE and some other text", canaries) == []


def test_fresh_npm_versions_are_hidden():
    doc = {
        "name": "pkg",
        "dist-tags": {"latest": "2.0.0", "beta": "2.1.0-beta"},
        "time": {
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "2.0.0": "2026-11-08T00:00:00.000Z",
            "2.1.0-beta": "2026-11-09T00:00:00.000Z",
        },
        "versions": {"1.0.0": {}, "2.0.0": {}, "2.1.0-beta": {}},
    }
    limit = packages.cutoff(7, now=datetime(2026, 11, 9, tzinfo=UTC))
    filtered = packages.filter_packument(doc, limit)
    assert list(filtered["versions"]) == ["1.0.0"]
    assert filtered["dist-tags"] == {"latest": "1.0.0"}


def test_tarball_coordinates():
    coords = packages.tarball_coordinates
    assert coords("/left-pad/-/left-pad-1.3.0.tgz") == ("left-pad", "1.3.0")
    assert coords("/@types/node/-/node-22.1.0.tgz") == ("@types/node", "22.1.0")
    assert coords("/@types%2fnode/-/node-22.1.0.tgz") == ("@types/node", "22.1.0")
    assert coords("/left-pad") is None
    assert packages.npm_packument_name("/@types%2fnode") == "@types/node"
    assert packages.npm_packument_name("/left-pad/-/left-pad-1.3.0.tgz") is None


def test_pypi_paths_and_age_filter():
    assert packages.pypi_index_project("/simple/Some_Pkg/") == "some-pkg"
    assert packages.pypi_index_project("/pypi/requests/json") is None
    whl = "/packages/aa/bb/cc/Requests_OAuth-2.0.0-py3-none-any.whl"
    assert packages.pypi_file_project(whl) == (
        "requests-oauth",
        "Requests_OAuth-2.0.0-py3-none-any.whl",
    )
    assert packages.pypi_file_project("/packages/x/foo-bar-1.0.tar.gz") == (
        "foo-bar",
        "foo-bar-1.0.tar.gz",
    )
    assert packages.pypi_file_project("/packages/x/README") is None
    index = {
        "files": [
            {"filename": "a-1.0.tar.gz", "upload-time": "2026-01-01T00:00:00Z"},
            {"filename": "a-2.0.tar.gz", "upload-time": "2026-11-08T00:00:00Z"},
            {"filename": "a-0.1.tar.gz"},
        ]
    }
    limit = packages.cutoff(7, now=datetime(2026, 11, 9, tzinfo=UTC))
    kept = packages.filter_simple_index(index, limit)["files"]
    assert [f["filename"] for f in kept] == ["a-1.0.tar.gz"]


def test_dependency_files_are_recognised_by_name():
    assert POLICY.is_dependency_file("package.json")
    assert POLICY.is_dependency_file("services/api/requirements-dev.txt")
    assert POLICY.is_dependency_file("uv.lock")
    assert not POLICY.is_dependency_file("src/package_info.js")
