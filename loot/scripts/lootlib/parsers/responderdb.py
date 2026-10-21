"""Responder's Responder.db to the credentials it captured and the clients it heard them from.

Reads the text copy ``sqlitedb`` renders: one ``responder <rowid>`` line per capture. A hash
reads as on the session log's ``Hash :`` line; a cleartext password is ``found``."""

from __future__ import annotations

import ipaddress
from typing import Any

from lootlib import records
from lootlib.encoding import NotText, text_of
from lootlib.parsers import Input, ParserError, creds, hashformats
from lootlib.parsers.nxcdb import Row, row_of

NAME = "responder-db"

COLUMNS = ("rowid", "module", "type", "client", "user", "cleartext", "hash", "fullhash")
COUNTED = ("Poisoned", "DHCP")


def claims(tables: dict[str, list[str]]) -> bool:
    return set(COLUMNS[1:]) <= set(tables.get("responder", ()))


def wanted(tables: dict[str, list[str]]) -> dict[str, tuple[str, ...]]:
    return {"responder": COLUMNS}


def sniff(data: bytes, hint: str | None = None) -> bool:
    return False


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    out, unread = [], 0
    for line in creds.lines(text):
        parsed = row_of(line)
        if parsed is None or parsed[0] != "responder":
            raise ParserError(f"not a rendered Responder database row: {line.text[:48]!r}")
        found = _capture(parsed[1], raw)
        unread += not found
        out += found
    if unread:
        raw.notices.append(f"{unread} capture(s) hold a hash Trove does not know, or no user, and were not "
                           "read; they are kept in the stored database")
    return out


def _capture(row: Row, raw: Input) -> list[dict[str, Any]]:
    """The credential a row holds and the host it came from: the client, for cleartext and NetNTLM."""
    if row["cleartext"]:
        rec = _cleartext(row, raw)
    else:
        rec = _hash(row, raw, "fullhash" if row["fullhash"] else "hash")
    if rec is None:
        return []
    host = _client(row, raw)
    if host is None or not (row["cleartext"] or rec["hash_type"].startswith("netntlm")):
        return [rec] + ([host] if host else [])
    records.set_field(rec, "host_id", [host["id"]], [host["prov"]["ip"]])
    return [host, rec]


def _cleartext(row: Row, raw: Input) -> dict[str, Any] | None:
    realm, _, principal = row["user"].rpartition("\\")
    if not principal:
        return None
    rec = records.new("credential")
    at = row.values["user"][1] + len(realm) + (1 if realm else 0)
    records.set_field(rec, "principal", principal, row.span(raw, at, at + len(principal)))
    if realm:
        records.set_field(rec, "realm", realm, row.span(raw, row.values["user"][1], row.values["user"][1] + len(realm)))
    records.set_field(rec, "secret", row["cleartext"], row.ref(raw, "cleartext"))
    records.set_field(rec, "state", creds.FOUND, row.ref(raw, "cleartext"))
    return rec


def _hash(row: Row, raw: Input, column: str) -> dict[str, Any] | None:
    value, at = row.values[column]
    typed = hashformats.match(value)
    if typed is None or typed.end != len(value) or not typed.principal:
        return None
    start = row.line.start + len(row.line.text[:at].encode("utf-8"))
    return creds.credential_from_typed(typed, creds.Line(value, start), raw)


def _client(row: Row, raw: Input) -> dict[str, Any] | None:
    try:
        ipaddress.ip_address(row["client"])
    except ValueError:
        return None
    host = records.new("host")
    records.set_field(host, "ip", row["client"], row.ref(raw, "client"))
    host["id"] = records.make_id(host)
    return host
