"""npm minimum-age policy: hide fresh versions so typosquats and hijacked releases can't land.

Standard library only: the proxy container imports this module as-is.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote


def cutoff(min_age_days: int, now: datetime | None = None) -> datetime:
    return (now or datetime.now(UTC)) - timedelta(days=min_age_days)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def old_enough(published: str | None, limit: datetime) -> bool:
    return published is not None and _parse(published) <= limit


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


def is_packument(path: str) -> bool:
    path = path.split("?", 1)[0]
    return path not in ("", "/") and "/-/" not in path and not path.endswith(".tgz")
