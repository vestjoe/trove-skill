"""masscan ``-oL``, ``-oJ``, ``-oD`` and screen output to hosts and services, every field cited.

A port's first banner is its ``banner``; every one is kept in ``ext.banners`` as ``<type>: <text>``.
A line of no masscan shape is left for AI extraction.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from lootlib import records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError
from lootlib.parsers.jsonspan import first_item, members
from lootlib.parsers.nmaptext import IP
from lootlib.prov import TOOL, cite

NAME = "masscan"
LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$")
STATES = "open|closed|up|unknown"
PROTOS = "tcp|udp|sctp|icmp|arp"
SERVICE_PROTOS = ("tcp", "udp", "sctp")

LIST_STATUS = re.compile(rf"^(?P<state>{STATES}) (?P<proto>{PROTOS}) (?P<port>\d{{1,5}}) (?P<ip>{IP}) \d+$")
LIST_BANNER = re.compile(
    rf"^banner (?P<proto>{PROTOS}) (?P<port>\d{{1,5}}) (?P<ip>{IP}) \d+ (?P<kind>\S+) (?P<banner>.*)$")
SCREEN_STATUS = re.compile(
    rf"^Discovered (?P<state>{STATES}) port (?P<port>\d{{1,5}})/(?P<proto>{PROTOS}) on (?P<ip>{IP})"
    r"(?: \((?P<mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\) ?(?P<vendor>.*?))? *$")
SCREEN_BANNER = re.compile(
    rf"^Banner on port (?P<port>\d{{1,5}})/(?P<proto>{PROTOS}) on (?P<ip>{IP}): \[(?P<kind>[^\]]*)\] (?P<banner>.*?) *$")
RUN_LINE = (r"Starting masscan \S+ \(http://bit\.ly/14GZzcT\) at .+|Initiating (?:SYN Stealth|ICMP Echo) Scan"
            r"|Scanning \d+ hosts(?: \[\d+ ports?/host\])?| -- forced options: .+"
            r"|rate: +[\d.]+-kpps, +[\d.]+% done, .+ found=\d+")
KNOWN = re.compile(rf"^(?:#masscan|# end|\[|,|\]|{RUN_LINE})\s*$")
NMAP = re.compile(r"^(?:Starting Nmap |Nmap scan report for )", re.MULTILINE)
_DECODER = json.JSONDecoder()

Span = tuple[Any, int, int]


@dataclass
class _Fact:
    """One masscan record: each value with its character span in the line."""

    ip: Span
    proto: Span
    port: Span
    state: Span | None = None
    kind: str = ""
    banner: Span | None = None
    ext: dict[str, Any] = field(default_factory=dict)


def sniff(data: bytes, hint: str | None = None) -> bool:
    text = data[:WINDOW].decode("utf-8", errors="replace")
    lines = [line.rstrip("\r\n") for line in LINE.findall(text)]
    if lines and lines[0].strip() == "#masscan":
        return True
    if any(_json_fact(line) is not None for line in lines[:50]):
        return True
    screen = any(SCREEN_STATUS.match(line) or SCREEN_BANNER.match(line) for line in lines)
    return screen and NMAP.search(text) is None


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    held: dict[str, dict[str, Any]] = {}
    offset = 0
    for chunk in LINE.findall(text):
        line = chunk.rstrip("\r\n")
        fact = _fact(line)
        if fact is not None:
            _record(fact, raw, offset, line, held)
        elif line.strip() and not KNOWN.match(line) and not WRAPPER.match(line):
            raw.unread.append(line)
        offset += len(chunk.encode("utf-8"))
    return list(held.values())


def _fact(line: str) -> _Fact | None:
    for shape in (LIST_STATUS, LIST_BANNER, SCREEN_STATUS, SCREEN_BANNER):
        found = shape.match(line)
        if found is not None:
            return _regex_fact(found)
    return _json_fact(line)


def _regex_fact(found: "re.Match[str]") -> _Fact:
    def span(name: str, value: Any = None) -> Span:
        return (found.group(name) if value is None else value), found.start(name), found.end(name)

    names = found.groupdict()
    fact = _Fact(span("ip"), span("proto"), span("port", int(found.group("port"))))
    if names.get("state") is not None:
        fact.state = span("state")
    if names.get("banner") is not None:
        fact.kind, fact.banner = found.group("kind"), span("banner")
    if names.get("mac"):
        fact.ext = {"mac": found.group("mac"), "mac_vendor": found.group("vendor")}
    return fact


def _json_fact(line: str) -> _Fact | None:
    """An ``-oD`` record or an ``-oJ`` record line; None for any other line."""
    if not line.lstrip().startswith("{"):
        return None
    try:
        start = len(line) - len(line.lstrip())
        _, end = _DECODER.raw_decode(line, start)
        if line[end:].strip():
            return None
        top = {k: (v, s, e) for k, v, s, e in members(line, start)}
        if "rec_type" in top:
            port, data = top, {k: (v, s, e) for k, v, s, e in members(line, top["data"][1])}
            status, banner, kind = data.get("status"), data.get("banner"), data.get("service_name")
        else:
            port = {k: (v, s, e) for k, v, s, e in members(line, first_item(line, top["ports"][1]))}
            service = {k: (v, s, e) for k, v, s, e in members(line, port["service"][1])} if "service" in port else {}
            status, banner, kind = port.get("status"), service.get("banner"), service.get("name")
            data = port
    except (ValueError, IndexError, KeyError, TypeError):
        return None
    ip, proto, number = top.get("ip"), port.get("proto"), port.get("port")
    if not (ip and proto and number and isinstance(ip[0], str) and type(number[0]) is int and proto[0] in PROTOS):
        return None
    fact = _Fact(_inner(ip), _inner(proto), number, _inner(status) if status else None)
    if banner is not None:
        fact.kind, fact.banner = str(kind[0]) if kind else "", _inner(banner)
    fact.ext = {k: data[k][0] for k in ("reason", "ttl") if k in data}
    return fact


def _inner(span: Span) -> Span:
    """A JSON string's span without its quotes."""
    value, start, end = span
    return (value, start + 1, end - 1) if isinstance(value, str) else span


def _record(fact: _Fact, raw: Input, line_at: int, line: str, held: dict[str, dict[str, Any]]) -> None:
    def ref(span: Span) -> dict[str, Any]:
        lo = line_at + len(line[:span[1]].encode("utf-8"))
        return cite(raw.blob, raw.data, lo, lo + len(line[span[1]:span[2]].encode("utf-8")), TOOL, raw.source)

    ip = fact.ip[0]
    host = held.get(f"host:{ip}")
    if host is None:
        host = held[f"host:{ip}"] = records.new("host")
        records.set_field(host, "ip", ip, ref(fact.ip))
    if fact.proto[0] not in SERVICE_PROTOS:
        if fact.state and fact.state[0] == "up" and "state" not in host:
            records.set_field(host, "state", "up", ref(fact.state))
        host["ext"].update({k: v for k, v in fact.ext.items() if v})
        return
    svc = records.new("service")
    records.set_field(svc, "host_id", f"host:{ip}", ref(fact.ip))
    records.set_field(svc, "port", fact.port[0], ref(fact.port))
    records.set_field(svc, "protocol", fact.proto[0], ref(fact.proto))
    svc = held.setdefault(records.make_id(svc), svc)
    if fact.state and "state" not in svc:
        records.set_field(svc, "state", fact.state[0], ref(fact.state))
    if fact.banner and fact.banner[0]:
        if "banner" not in svc:
            records.set_field(svc, "banner", fact.banner[0], ref(fact.banner))
        _add_banner(svc, f"{fact.kind}: {fact.banner[0]}")
    svc["ext"].update(fact.ext)


def _add_banner(svc: dict[str, Any], banner: str) -> None:
    if banner not in svc["ext"].setdefault("banners", []):
        svc["ext"]["banners"].append(banner)
