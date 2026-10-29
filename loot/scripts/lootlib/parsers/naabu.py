"""naabu ``-json`` output, one object per open port, to hosts and services, every field cited.

A line that is not an object with ``ip``, ``port`` and ``protocol`` is left for AI extraction.
"""

from __future__ import annotations

import json
from itertools import islice
from typing import Any

from lootlib import records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError, split_lines
from lootlib.parsers.jsonspan import members
from lootlib.prov import TOOL, cite

NAME = "naabu"
SERVICE_FIELDS = ("name", "product", "version", "banner")
SERVICE_EXT = ("tls", "cdn", "cdn-name", "tunnel", "extra_info", "method", "confidence", "cpes", "hostname",
               "os_type", "device_type")
_DECODER = json.JSONDecoder()

Span = tuple[Any, int, int]


def sniff(data: bytes, hint: str | None = None) -> bool:
    text = data[:WINDOW].decode("utf-8", errors="replace")
    return any(_result(line) is not None for line, _ in islice(split_lines(text), 50))


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    held: dict[str, dict[str, Any]] = {}
    for line, offset in split_lines(text):
        found = _result(line)
        if found is not None:
            _records(found, raw, offset, line, held)
        elif line.strip() and not WRAPPER.match(line):
            raw.unread.append(line)
    return list(held.values())


def _result(line: str) -> dict[str, Span] | None:
    """The members of a naabu result line with their spans, or None for any other line."""
    if not line.startswith("{"):
        return None
    try:
        whole, end = _DECODER.raw_decode(line)
        found = {key: (value, start, stop) for key, value, start, stop in members(line)}
    except (ValueError, IndexError):
        return None
    if line[end:].strip() or not isinstance(whole, dict):
        return None
    ip, port, protocol = (found.get(k, (None,))[0] for k in ("ip", "port", "protocol"))
    if not (isinstance(ip, str) and ip and type(port) is int and isinstance(protocol, str) and protocol):
        return None
    return found


def _records(found: dict[str, Span], raw: Input, line_at: int, line: str,
             held: dict[str, dict[str, Any]]) -> None:
    def ref(key: str) -> dict[str, Any]:
        value, start, end = found[key]
        if isinstance(value, str):
            start, end = start + 1, end - 1
        lo = line_at + len(line[:start].encode("utf-8"))
        return cite(raw.blob, raw.data, lo, lo + len(line[start:end].encode("utf-8")), TOOL, raw.source)

    ip = found["ip"][0]
    host = held.get(f"host:{ip}")
    if host is None:
        host = held[f"host:{ip}"] = records.new("host")
        records.set_field(host, "ip", ip, ref("ip"))
    name = found.get("host", (None,))[0]
    if isinstance(name, str) and name and name != ip and name not in host.get("hostnames", []):
        records.set_field(host, "hostnames", host.get("hostnames", []) + [name],
                          host["prov"].get("hostnames", []) + [ref("host")])
    for key, ext in (("mac_address", "mac"), ("mac_vendor", "mac_vendor"), ("os", "os")):
        if found.get(key, (None,))[0]:
            host["ext"][ext] = found[key][0]

    svc = records.new("service")
    records.set_field(svc, "host_id", f"host:{ip}", ref("ip"))
    records.set_field(svc, "port", found["port"][0], ref("port"))
    records.set_field(svc, "protocol", found["protocol"][0], ref("protocol"))
    for key in SERVICE_FIELDS:
        if isinstance(found.get(key, (None,))[0], str) and found[key][0]:
            records.set_field(svc, key, found[key][0], ref(key))
    for key in SERVICE_EXT:
        if found.get(key, (None,))[0] not in (None, "", []):
            svc["ext"][key] = found[key][0]
    held.setdefault(records.make_id(svc), svc)
