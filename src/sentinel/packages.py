"""Package controls: hide fresh releases and, optionally, anything not on an allowlist.

Fresh releases are where typosquats and hijacked versions land, so npm versions and PyPI files
younger than the minimum age are filtered out of registry metadata and their downloads refused.

Standard library only: the proxy container imports this module as-is.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

PYPI_JSON = "application/vnd.pypi.simple.v1+json"  # PEP 691, with upload times from PEP 700
SDIST_SUFFIXES = (".tar.gz", ".tar.bz2", ".zip")


def cutoff(min_age_days: int, now: datetime | None = None) -> datetime:
    return (now or datetime.now(UTC)) - timedelta(days=min_age_days)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def old_enough(published: str | None, limit: datetime) -> bool:
    return published is not None and _parse(published) <= limit


def allowed(name: str, allowlist: tuple[str, ...]) -> bool:
    """An empty allowlist allows everything that passes the age check."""
    return not allowlist or name in allowlist


# npm ------------------------------------------------------------------------


def npm_packument_name(path: str) -> str | None:
    path = unquote(path.split("?", 1)[0]).strip("/")
    return path if path and "/-/" not in path and not path.endswith(".tgz") else None


def filter_packument(doc: dict[str, Any], limit: datetime) -> dict[str, Any]:
    """Drop versions published after `limit` and repoint dist-tags at what's left."""
    times = doc.get("time", {})
    versions = doc.get("versions", {})
    kept = {v: meta for v, meta in versions.items() if old_enough(times.get(v), limit)}
    tags = {tag: v for tag, v in doc.get("dist-tags", {}).items() if v in kept}
    if "latest" not in tags and kept:
        tags["latest"] = max(kept, key=lambda v: _parse(times[v]))
    return {**doc, "versions": kept, "dist-tags": tags}


def tarball_coordinates(path: str) -> tuple[str, str] | None:
    """'/@scope/pkg/-/pkg-1.2.3.tgz' -> ('@scope/pkg', '1.2.3')."""
    path = unquote(path.split("?", 1)[0])
    if "/-/" not in path or not path.endswith(".tgz"):
        return None
    name, filename = path.lstrip("/").split("/-/", 1)
    prefix = name.rsplit("/", 1)[-1] + "-"
    if not filename.startswith(prefix):
        return None
    return name, filename[len(prefix) : -len(".tgz")]


# PyPI -----------------------------------------------------------------------


def normalise(name: str) -> str:
    """PEP 503 project name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_index_project(path: str) -> str | None:
    """'/simple/Some_Pkg/' -> 'some-pkg'."""
    parts = path.split("?", 1)[0].strip("/").split("/")
    return normalise(parts[1]) if len(parts) == 2 and parts[0] == "simple" else None


def pypi_file_project(path: str) -> tuple[str, str] | None:
    """'/packages/../requests-2.32.3-py3-none-any.whl' -> ('requests', filename)."""
    filename = unquote(path.split("?", 1)[0]).rsplit("/", 1)[-1]
    if filename.endswith(".whl"):
        return normalise(filename.split("-", 1)[0]), filename
    for suffix in SDIST_SUFFIXES:
        if filename.endswith(suffix) and "-" in filename:
            return normalise(filename[: -len(suffix)].rsplit("-", 1)[0]), filename
    return None


def upload_times(index: dict[str, Any]) -> dict[str, str]:
    return {f["filename"]: f.get("upload-time") for f in index.get("files", [])}


def filter_simple_index(index: dict[str, Any], limit: datetime) -> dict[str, Any]:
    """Drop files uploaded after `limit`. Files without an upload time are dropped too."""
    files = [f for f in index.get("files", []) if old_enough(f.get("upload-time"), limit)]
    return {**index, "files": files}
