"""The agent's proposed records, checked against the stored bytes before any is written.

The model proposes, code records.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from lootlib import rawstore, records
from lootlib.engagement import Engagement
from lootlib.errors import LootError
from lootlib.prov import AI, cite, contains, find_quote, whole

ALIASES = {"host": "host_id", "service": "service_id", "ip_address": "ip"}
AI_TYPES = ("host", "service", "credential", "principal", "group", "share", "finding", "note")
VERBATIM = {
    "host": {"ip", "hostnames"},
    "service": {"host_id", "port", "name", "product", "version"},
    "credential": {"principal", "realm", "secret", "secret_hash", "host_id"},
    "principal": {"principal", "realm", "sid"},
    "group": {"name", "realm", "sid"},
    "share": {"host_id", "name"},
    "finding": {"host_id"},
    "note": {"host_id"},
}
REFUSED = {"severity": "severity is a judgement no input states, so it is never stored",
           "hosts": "a credential's hosts come only from a tool's confirmed login",
           "admin_hosts": "admin access comes only from a tool's (Pwn3d!) login",
           "banner": "a banner is what a service sent a scanner, so only a tool's output records it"}
EXACT = {"secret_hash", "principal", "hostnames"}
AI_STATE = "found"


def _ip(text: str) -> str:
    return str(ipaddress.ip_address(str(text).strip()))


def _coerce(type_name: str, name: str, value: Any) -> Any:
    """The stored form of a proposed value; raises ValueError when it is not one."""
    if name == "port":
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError("port must be 1-65535")
        return port
    if name == "protocol":
        if str(value).lower() not in ("tcp", "udp"):
            raise ValueError("protocol must be tcp or udp")
        return str(value).lower()
    if name == "ip":
        return _ip(value)
    if name == "host_id":
        linked = "host:" + _ip(str(value).removeprefix("host:"))
        return [linked] if (type_name, name) in records.LIST_FIELDS else linked
    if (type_name, name) in records.LIST_FIELDS:
        return [str(v) for v in (value if isinstance(value, list) else [value])]
    if isinstance(value, (dict, list)):
        raise ValueError("expected a single value")
    return str(value)


def _host_named(name: str, held: dict[str, dict[str, Any]]) -> str:
    """The id of the one held host carrying ``name`` as a hostname or its first label.
    Raises ValueError when no host or more than one does."""
    want = name.strip().casefold()
    ids = {r["id"] for r in held.values() if r["type"] == "host"
           and any(want in (h.casefold(), h.casefold().split(".")[0]) for h in r.get("hostnames") or [])}
    if len(ids) != 1:
        raise ValueError(f"names {'no host' if not ids else f'{len(ids)} hosts'} Trove holds; "
                         "a host link needs an IP or a hostname exactly one host carries")
    return ids.pop()


def check(eng: Engagement, blob: str, text: str, chunk: int | None = None) -> dict[str, Any]:
    """Validate a proposal JSON for one chunk of ``blob`` (default: the next not yet covered);
    writes what survives and reports every drop. The blob is done once every chunk is."""
    entry = rawstore.entry(eng, blob)
    left, total = rawstore.chunks_left(eng, entry)
    chunk = chunk if chunk is not None else (left[0] if left else total)
    if not 1 <= chunk <= total:
        raise LootError(f"{entry['source']} has {total} chunk(s); --chunk {chunk} is out of range")
    data = rawstore.read(eng, entry["blob"])
    try:
        proposal = json.loads(text)
    except json.JSONDecodeError as err:
        raise LootError(f"proposal is not valid JSON: {err.msg} at line {err.lineno} column {err.colno}") from err
    items = proposal.get("records") if isinstance(proposal, dict) else None
    if not isinstance(items, list):
        raise LootError('proposal must be an object with a "records" list')

    held = records.load_all(eng)
    accepted, dropped = [], []
    for n, item in enumerate(items, 1):
        where = f"record {n}"
        type_name = item.get("type") if isinstance(item, dict) else None
        if type_name not in AI_TYPES:
            dropped.append(f"{where}: type {type_name!r} is not one of {', '.join(AI_TYPES)}")
            continue
        rec = records.new(type_name)
        fields = item.get("fields") or {}
        for raw_name, proposed in fields.items():
            name = ALIASES.get(raw_name, raw_name)
            label = f"{where} ({type_name}).{raw_name}"
            if name in REFUSED:
                dropped.append(f"{label}: {REFUSED[name]}")
                continue
            if (type_name, name) == ("credential", "state") and isinstance(proposed, dict) \
                    and "value" in proposed and proposed["value"] != AI_STATE:
                dropped.append(f"{label}: only a tool's crack or login makes a credential cracked or confirmed; "
                               f"a proposal may say {AI_STATE!r}")
                continue
            if type_name == "finding" and name in ("status", "suggested_status") and isinstance(proposed, dict) \
                    and "value" in proposed:
                allowed = ("open",) if name == "status" else records.DECIDED
                if proposed["value"] not in allowed:
                    dropped.append(f"{label}: " + ("a tool or you set a finding's status; a proposal leaves it "
                                                   "open and puts its view in suggested_status"
                                                   if name == "status" else f"must be one of {', '.join(allowed)}"))
                    continue
            if name not in records.TYPES[type_name]:
                dropped.append(f"{label}: not a {type_name} field")
                continue
            if not isinstance(proposed, dict) or "value" not in proposed or "evidence" not in proposed:
                dropped.append(f"{label}: needs {{\"value\": ..., \"evidence\": ...}}")
                continue
            evidence = str(proposed["evidence"])
            located = find_quote(data, evidence)
            if located is None:
                dropped.append(f"{label}: evidence is not in the file: {evidence[:60]!r}")
                continue
            named = None
            try:
                value = _coerce(type_name, name, proposed["value"])
            except (ValueError, TypeError) as err:
                if name != "host_id" or isinstance(proposed["value"], (dict, list)):
                    dropped.append(f"{label}: {err}")
                    continue
                named = str(proposed["value"]).removeprefix("host:").strip()
            ref = cite(entry["blob"], data, *located, AI, entry["source"])
            if named is not None:
                if not contains(ref["quote"], named):
                    dropped.append(f"{label}: value {proposed['value']!r} does not appear in its evidence")
                    continue
                try:
                    value = _host_named(named, held)
                    value = [value] if (type_name, name) in records.LIST_FIELDS else value
                except ValueError as err:
                    dropped.append(f"{label}: {named!r} {err}")
                    continue
            elif name == "secret":
                if not whole(ref["quote"], value):
                    dropped.append(f"{label}: value {proposed['value']!r} is not a whole password in its evidence, "
                                   "character for character; a password is never stored cut short or re-spaced")
                    continue
            elif name == "principal" and type_name == "credential" and value == records.UNKNOWN_USER:
                pass
            elif name in VERBATIM.get(type_name, ()):
                exact = name in EXACT and not (name == "secret_hash" and records.is_hex(value))
                parts = [str(p).removeprefix("host:") for p in (value if isinstance(value, list) else [value])]
                if not all(contains(ref["quote"], p, exact=exact) for p in parts):
                    dropped.append(f"{label}: value {proposed['value']!r} does not appear in its evidence")
                    continue
            records.set_field(rec, name, value, [ref] * len(value) if isinstance(value, list) else ref)
        if type_name == "finding" and "title" in rec["prov"] and "status" not in rec["prov"] \
                and records.make_id(rec) not in held:
            records.set_field(rec, "status", "open", rec["prov"]["title"])
        if rec.get("principal") == records.UNKNOWN_USER and not ({"secret", "secret_hash"} & rec["prov"].keys()):
            dropped.append(f"{where} (credential): not written, {records.UNKNOWN_USER} stands for no account "
                           "and is kept only with the password or hash it was written beside")
            continue
        missing = [k for k in records.KEY_FIELDS[type_name] if k not in rec["prov"]]
        if missing:
            dropped.append(f"{where} ({type_name}): not written, its {', '.join(missing)} was missing or dropped")
            continue
        accepted.append(rec)

    new, updated = records.put_all(eng, accepted)
    remaining = [n for n in left if n != chunk]
    done = sorted(set(entry.get("chunks_done", [])) | {chunk})
    rawstore.update(eng, entry["blob"], chunks_done=done, **({} if remaining else {"ai": "done"}))
    return {"blob": entry["blob"], "accepted": len(accepted), "new": new, "updated": updated, "dropped": dropped,
            "chunk": chunk, "chunks": total, "remaining": remaining}
