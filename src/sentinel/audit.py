"""Append-only JSONL audit log. Standard library only: the proxy imports it too."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def record(log: Path, event: str, /, **fields: Any) -> None:
    line = json.dumps({"ts": round(time.time(), 3), "event": event, **fields}, default=str)
    with Path(log).open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read(log: Path) -> list[dict[str, Any]]:
    if not Path(log).exists():
        return []
    events = []
    for line in Path(log).read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # partial line while the writer is mid-append
    return events
