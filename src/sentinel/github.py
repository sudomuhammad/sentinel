"""Minimal GitHub App client: short-lived, single-repo tokens, issue reads and pull requests.

Configure with SENTINEL_GITHUB_APP_ID and SENTINEL_GITHUB_APP_KEY_FILE (the App's private key).
The key and every token stay on the host; the sandbox never sees them.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

import jwt

API = "https://api.github.com"
TOKEN_PERMISSIONS = {"contents": "write", "pull_requests": "write", "issues": "read"}


def _call(method: str, path: str, auth: str, body: dict | None = None) -> Any:
    req = urllib.request.Request(  # noqa: S310 - fixed https host
        f"{API}{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": auth,
            "User-Agent": "sentinel",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.load(resp)


def _app_jwt() -> str:
    app_id = os.environ["SENTINEL_GITHUB_APP_ID"]
    key = Path(os.environ["SENTINEL_GITHUB_APP_KEY_FILE"]).read_text()
    now = int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": app_id}, key, algorithm="RS256")


def installation_token(slug: str) -> str:
    """A token for this one repository that expires within the hour."""
    app_auth = f"Bearer {_app_jwt()}"
    installation = _call("GET", f"/repos/{slug}/installation", app_auth)
    body = {"repositories": [slug.split("/", 1)[1]], "permissions": TOKEN_PERMISSIONS}
    return _call("POST", f"/app/installations/{installation['id']}/access_tokens", app_auth, body)[
        "token"
    ]


def git_auth_env(token: str) -> dict[str, str]:
    """Git config via environment, so the token never lands in argv or .git/config."""
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
    }


def fetch_issue(slug: str, number: int, token: str) -> str:
    issue = _call("GET", f"/repos/{slug}/issues/{number}", f"token {token}")
    return f"{issue['title']}\n\n{issue.get('body') or ''}"


def open_pull_request(slug: str, token: str, head: str, base: str, title: str, body: str) -> str:
    payload = {"title": title, "head": head, "base": base, "body": body}
    return _call("POST", f"/repos/{slug}/pulls", f"token {token}", payload)["html_url"]
