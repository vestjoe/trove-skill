"""JSON objects with the character span of each member's value, for citing one-line records."""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

_DECODER = json.JSONDecoder()
_WS = re.compile(r"\s*")


def members(text: str, at: int = 0) -> Iterator[tuple[str, Any, int, int]]:
    """Each member of the JSON object whose ``{`` is at ``at``: key, value and the value's span.
    Raises ``ValueError`` or ``IndexError`` on text that is not such an object."""
    if text[at] != "{":
        raise ValueError(f"no object at {at}")
    at = _WS.match(text, at + 1).end()
    while text[at] != "}":
        key, key_end = _DECODER.raw_decode(text, at)
        start = _WS.match(text, _WS.match(text, key_end).end() + 1).end()
        value, end = _DECODER.raw_decode(text, start)
        yield key, value, start, end
        at = _WS.match(text, end).end()
        at = _WS.match(text, at + 1).end() if text[at] == "," else at


def first_item(text: str, at: int) -> int:
    """Where the first element of the JSON array whose ``[`` is at ``at`` starts."""
    return _WS.match(text, at + 1).end()
