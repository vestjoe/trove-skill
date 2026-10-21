"""Citations: every structured field points at the bytes it came from."""

from __future__ import annotations

import re
from typing import Any

from lootlib.errors import LootError

TOOL, AI, YOU = "tool", "ai", "you"
AUTHORITY = {AI: 0, TOOL: 1, YOU: 2}
ORIGINS_HELP = {TOOL: "a parser read it", AI: "the agent proposed it and its quote checked out", YOU: "you wrote it"}

_LEFT_EDGE = r"(?<![\w-])(?<!\w\.)"
_RIGHT_EDGE = r"(?![\w-])(?!\.\w)"
_SEPARATOR = r"[\s\"'`“”‘’«»,;:&@/\\<>()\[\]{}|*%=]"
_TOKEN_LEFT = rf"(?:^|(?<={_SEPARATOR}))"
_TOKEN_RIGHT = rf"(?=$|{_SEPARATOR}|[.?]+(?:$|{_SEPARATOR}))"


def cite(blob: str, data: bytes, start: int, end: int, origin: str, source: str = "") -> dict[str, Any]:
    """A citation built by quoting the bytes rather than being told what they say."""
    if start < 0 or end < start or end > len(data):
        raise LootError(f"span {start}:{end} is outside the blob ({len(data)} bytes)")
    try:
        quote = data[start:end].decode("utf-8")
    except UnicodeDecodeError as err:
        raise LootError(f"span {start}:{end} is not UTF-8 text") from err
    ref = {"blob": blob, "span": [start, end], "quote": quote, "origin": origin}
    if source:
        ref["source"] = source
    return ref


def find_quote(data: bytes, quote: str) -> tuple[int, int] | None:
    """Byte span of ``quote`` in ``data``: exact first, then with any run of whitespace equal."""
    if not quote.strip():
        return None
    needle = quote.encode("utf-8")
    at = data.find(needle)
    if at >= 0:
        return at, at + len(needle)
    words = quote.split()
    found = re.search(rb"\s+".join(re.escape(w.encode("utf-8")) for w in words), data)
    return (found.start(), found.end()) if found else None


def contains(quote: str, value: str, exact: bool = False) -> bool:
    """Does ``quote`` hold ``value`` whole, never inside a longer value; case-insensitive
    unless ``exact``."""
    words = str(value).split()
    if not words:
        return True
    pattern = _LEFT_EDGE + r"\s+".join(re.escape(w) for w in words) + _RIGHT_EDGE
    return re.search(pattern, quote, flags=0 if exact else re.IGNORECASE) is not None


def whole(quote: str, value: str) -> bool:
    """Does ``quote`` hold ``value`` exactly, between separators (whitespace, quotes, ``:,;@/%=`` and
    the like), or before sentence ``.``/``?``; refuses a value with whitespace at either end."""
    if not value or value != value.strip() or "\n" in value:
        return False
    pattern = _TOKEN_LEFT + re.escape(value) + _TOKEN_RIGHT
    return re.search(pattern, quote, flags=re.MULTILINE) is not None


def origin_of(citation: Any) -> str:
    """The origin a field's citation (or list of citations) carries; the strongest wins."""
    refs = citation if isinstance(citation, list) else [citation]
    return max((r["origin"] for r in refs), key=AUTHORITY.__getitem__)
