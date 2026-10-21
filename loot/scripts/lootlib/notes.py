"""Operator notes and decisions: kept as raw blobs, recorded with origin ``you``."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from lootlib import find, rawstore, records
from lootlib.engagement import Engagement
from lootlib.errors import LootError
from lootlib.prov import YOU, cite

_SLUG = re.compile(r"[^a-z0-9]+")


def host_id(given: str, held: dict[str, dict[str, Any]] | None = None) -> str:
    """``host:<ip>`` from a host id, a bare IP, or the name of exactly one held host;
    refuses a name that matches no host or several."""
    try:
        return "host:" + str(ipaddress.ip_address(given.strip().removeprefix("host:")))
    except ValueError:
        pass
    named = find.host_ids_named(held or {}, given)
    if len(named) == 1:
        return named[0]
    if named:
        raise LootError(f"--host {given!r} names {len(named)} hosts ({', '.join(named)}); give the IP")
    raise LootError(f"--host {given!r} is not an IP and no host Trove holds is called that")


def add(eng: Engagement, data: bytes, host: str | None = None, tags: list[str] | None = None) -> dict[str, Any]:
    """Store note bytes, write its note file and record, and mark a new blob pending.
    Refuses empty or non-UTF-8 text and a bad --host."""
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise LootError("a note must be UTF-8 text") from None
    if not text:
        raise LootError("a note needs some text")
    linked = host_id(host, records.load_all(eng)) if host else None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"notes/{stamp}-{_SLUG.sub('-', text.lower()[:40]).strip('-') or 'note'}.md"
    blob, is_new = rawstore.put(eng, data, name, ai="pending")
    if is_new:
        (eng.root / name).write_bytes(data)
    else:
        name = rawstore.entry(eng, blob)["source"]
    start = data.index(text.encode("utf-8"))
    rec = records.new("note")
    records.set_field(rec, "text", text, cite(blob, data, start, start + len(text.encode("utf-8")), YOU, name))
    given = {"blob": blob, "origin": YOU, "source": name}
    if tags:
        unique = list(dict.fromkeys(tags))
        records.set_field(rec, "tags", unique, [dict(given, quote=t) for t in unique])
    if linked:
        records.set_field(rec, "host_id", linked, dict(given, quote=host))
    new, _ = records.put_all(eng, [rec])
    pending = rawstore.entry(eng, blob)["ai"] == "pending"
    return {"id": records.make_id(rec), "file": name, "blob": blob, "new": bool(new), "pending": pending}


def set_status(eng: Engagement, rid: str, value: str) -> dict[str, Any]:
    """Set a held finding's ``status`` as the operator's decision, cited to the command's own text.
    Refuses another record type, an unknown id and a value outside the set."""
    held = records.load_all(eng).get(rid)
    if held is None or held["type"] != "finding":
        raise LootError(f"{rid!r} is not a finding Trove holds; find --type finding lists them")
    if value not in records.STATUSES:
        raise LootError(f"status must be one of {', '.join(records.STATUSES)}")
    data = f"loot set {rid} status={value}\n".encode("utf-8")
    blob, _ = rawstore.put(eng, data, f"decisions/{_SLUG.sub('-', rid.lower())[:60]}-{value}.txt")
    start = data.index(f"={value}".encode("utf-8")) + 1
    rec = dict(held, prov=dict(held["prov"]))
    records.set_field(rec, "status", value, cite(blob, data, start, start + len(value.encode("utf-8")), YOU,
                                                 rawstore.entry(eng, blob)["source"]))
    records.put_all(eng, [rec])
    return {"id": rid, "status": value, "blob": blob}
