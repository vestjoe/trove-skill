"""Raw input, stored verbatim and content-addressed, with a manifest line per blob."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from typing import Any

from lootlib.engagement import Engagement
from lootlib.errors import LootError

CHUNK = 12_000


def blob_id(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _path(eng: Engagement, blob: str):
    if not blob.startswith("sha256:"):
        raise LootError(f"{blob!r} is not a blob id (expected sha256:<hex>)")
    return eng.raw / blob.removeprefix("sha256:")


def manifest(eng: Engagement) -> list[dict[str, Any]]:
    path = eng.raw / "manifest.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def entry(eng: Engagement, blob: str) -> dict[str, Any]:
    """The manifest line for a blob; a full id or a unique prefix of one."""
    want = blob if blob.startswith("sha256:") else "sha256:" + blob
    hits = [m for m in manifest(eng) if m["blob"].startswith(want)]
    if len(hits) != 1:
        raise LootError(f"{blob!r} matches {len(hits)} stored blobs; give more of the id")
    return hits[0]


def put(eng: Engagement, data: bytes, source: str, *, parser: str | None = None,
        derived_from: str | None = None, encoding: str | None = None, ai: str = "n/a") -> tuple[str, bool]:
    """Store bytes once; returns the blob id and whether it was new. Never overwrites."""
    blob = blob_id(data)
    path = _path(eng, blob)
    if path.exists():
        return blob, False
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    line = {"blob": blob, "source": source, "size": len(data),
            "imported": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "parser": parser, "derived_from": derived_from, "encoding": encoding, "ai": ai}
    with (eng.raw / "manifest.jsonl").open("a") as fh:
        fh.write(json.dumps(line) + "\n")
    return blob, True


def update(eng: Engagement, blob: str, **changes: Any) -> None:
    """Change fields of one manifest line (parser, ai status); rewrites the small manifest."""
    lines = manifest(eng)
    for line in lines:
        if line["blob"] == blob:
            line.update(changes)
    tmp = eng.raw / "manifest.jsonl.tmp"
    tmp.write_text("".join(json.dumps(line) + "\n" for line in lines))
    os.replace(tmp, eng.raw / "manifest.jsonl")


def read(eng: Engagement, blob: str) -> bytes:
    path = _path(eng, blob)
    if not path.exists():
        raise LootError(f"no stored blob {blob}")
    return path.read_bytes()


def chunks(data: bytes, size: int = CHUNK) -> list[tuple[int, int]]:
    """Byte ranges of about ``size``, cut after a newline where one is near."""
    spans, start = [], 0
    while start < len(data):
        end = min(start + size, len(data))
        if end < len(data):
            cut = data.rfind(b"\n", start, end)
            if cut > start:
                end = cut + 1
        spans.append((start, end))
        start = end
    return spans or [(0, 0)]


def chunks_left(eng: Engagement, entry: dict[str, Any]) -> tuple[list[int], int]:
    """Chunk numbers of a blob no proposal has covered yet, and how many chunks it has."""
    total = len(chunks(read(eng, entry["blob"])))
    done = set(entry.get("chunks_done", []))
    return [n for n in range(1, total + 1) if n not in done], total
