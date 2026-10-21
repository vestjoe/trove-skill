"""A plain list of usernames to principal-only credentials; reached only by ``--tool users``.

Blank and ``#`` lines are skipped, a repeated name is one record, and the rest of a line is
the principal verbatim (``DOMAIN\\user`` is not split)."""

from __future__ import annotations

from typing import Any

from lootlib import records
from lootlib.encoding import NotText, text_of
from lootlib.parsers import Input, ParserError
from lootlib.prov import TOOL, cite

NAME = "users"
COMMENT = "#"


def sniff(data: bytes, hint: str | None = None) -> bool:
    return False


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    out: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    offset = 0
    for line in text.splitlines(keepends=True):
        start = offset
        offset += len(line.encode("utf-8"))
        principal = line.rstrip("\r\n").strip()
        if not principal or principal.startswith(COMMENT):
            continue
        if principal in seen:
            seen[principal] += 1
            continue
        seen[principal] = 1
        at = start + len(line[: line.index(principal)].encode("utf-8"))
        rec = records.new("credential")
        records.set_field(rec, "principal", principal,
                          cite(raw.blob, raw.data, at, at + len(principal.encode("utf-8")), TOOL, raw.source))
        out.append(rec)
    if repeats := sum(count - 1 for count in seen.values()):
        raw.notices.append(f"{repeats} repeated name(s) in {raw.source or 'the list'} became one record each. "
                           "The file is stored in raw/ exactly as it arrived.")
    if not out:
        raw.notices.append(f"no names in {raw.source or 'the list'}: every line was blank or a {COMMENT} comment. "
                           "Nothing was recorded; the file is in raw/.")
    return out
