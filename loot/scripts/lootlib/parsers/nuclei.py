"""nuclei results (``-j``/``-jle`` JSONL, a ``-je`` array, ``-o`` and screen text) to hosts, tcp services
and findings, every field cited.

A result nuclei reports as failed (``-ms``) makes no finding. A line that is not nuclei's goes to AI extraction.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from itertools import islice
from typing import Any
from urllib.parse import urlsplit

from lootlib import records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError, split_lines
from lootlib.parsers.jsonspan import first_item, members
from lootlib.prov import TOOL, cite

NAME = "nuclei"
TYPES = ("http", "dns", "tcp", "ssl", "javascript", "file", "headless", "code", "whois", "websocket", "dast",
         "flow", "multiprotocol", "workflow", "network")
SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")
SERVICE_TYPES = ("http", "ssl", "tcp")
INFO_EXT = ("tags", "reference")
CLASSIFICATION_EXT = ("cve-id", "cwe-id", "cvss-score")
_DECODER = json.JSONDecoder()
_JSON_START = re.compile(r'^\[?\{"template(?:-url|-id|-path)?":')
_SCREEN = re.compile(
    r"^(?:\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] )?\[(?P<id>[^\]\s:]+)(?::(?P<sub>[^\]]+))?\]"
    r"(?: \[(?P<status>matched|failed)\])?(?: \[global\])?"
    rf" \[(?P<type>{'|'.join(TYPES)})\] \[(?P<severity>{'|'.join(SEVERITIES)})\] (?P<target>\S+)(?: (?P<rest>.+))?$")
_LOG = re.compile(r"^\[(?:INF|WRN|ERR|FTL|DBG|VER)\] .+$")
_BANNER = {"__     _", "____  __  _______/ /__  (_)", "/ __ \\/ / / / ___/ / _ \\/ /", "/ / / / /_/ / /__/ /  __/ /",
           "projectdiscovery.io"}
_BANNER_VERSION = re.compile(r"^/_/ /_/\\__,_/\\___/_/\\___/_/   v[\w.-]+$")

Span = tuple[Any, int, int]


@dataclass
class _Result:
    """One nuclei result: each value with its byte span in the blob, or None."""

    template_id: Span
    stated: Span
    type: Span
    severity: str
    sub: str = ""
    target: Span | None = None
    ip: Span | None = None
    host: Span | None = None
    port: Span | None = None
    name: Span | None = None
    ext: dict[str, Any] = field(default_factory=dict)
    lists: dict[str, Any] = field(default_factory=dict)


def sniff(data: bytes, hint: str | None = None) -> bool:
    text = data[:WINDOW].decode("utf-8", errors="replace")
    for line, _ in islice(split_lines(text), 50):
        if (_JSON_START.match(line) and '"template-id":' in line) or _SCREEN.match(line):
            return True
    return False


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    held: dict[str, dict[str, Any]] = {}
    failed, waiting = 0, set()
    for line, offset in split_lines(text):
        found = _results(line, offset)
        if found is None:
            if line.strip() and not _known(line):
                raw.unread.append(line)
            continue
        for result in found:
            if result is None:
                failed += 1
            elif not _records(result, raw, held):
                waiting.add(result.host[0])
    if failed:
        raw.notices.append(f"{raw.source}: {failed} result(s) nuclei reported as failed (-ms) make no finding.")
    if waiting:
        raw.unresolved.append("host")
        raw.notices.append(f"{raw.source}: the results on {', '.join(sorted(waiting))} wait for a scan that names "
                           "that host; each lands on it once Trove holds it.")
    return list(held.values())


def _known(line: str) -> bool:
    return bool(WRAPPER.match(line) or _LOG.match(line) or line.strip() in _BANNER or _BANNER_VERSION.match(line))


def _results(line: str, offset: int) -> list[_Result | None] | None:
    """The results on one line (None for a failed one), or None when the line is not nuclei's."""
    def at(i: int) -> int:
        return offset + len(line[:i].encode("utf-8"))

    if line == "[]":
        return []
    if line.startswith("{"):
        found = _object(line, 0, at)
        return None if found is False else [found]
    if line.startswith("[{"):
        try:
            out, i = [], first_item(line, 0)
            while True:
                found = _object(line, i, at)
                if found is False:
                    return None
                out.append(found)
                i = _DECODER.raw_decode(line, i)[1]
                i = len(line) - len(line[i:].lstrip())
                if line[i] == "]" and not line[i + 1:].strip():
                    return out
                if line[i] != ",":
                    return None
                i = len(line) - len(line[i + 1:].lstrip())
        except (ValueError, IndexError):
            return None
    shown = _SCREEN.match(line)
    return None if shown is None else [_screen(shown, at)]


def _object(line: str, start: int, at) -> _Result | None | bool:
    """The result object whose ``{`` is at ``start``; None if failed, False if it is not a result."""
    try:
        end = _DECODER.raw_decode(line, start)[1]
        found = {k: (v, s, e) for k, v, s, e in members(line, start)}
    except (ValueError, IndexError):
        return False
    if start == 0 and line[end:].strip():
        return False
    tid, info = found.get("template-id"), found.get("info")
    if not (tid and isinstance(tid[0], str) and tid[0] and info and isinstance(info[0], dict)):
        return False
    if found.get("matcher-status", (True,))[0] is False:
        return None

    def span(member: tuple[Any, int, int] | None) -> Span | None:
        if member is None or member[0] in (None, "", [], {}):
            return None
        value, s, e = member
        if isinstance(value, str):
            s, e = s + 1, e - 1
        return value, at(s), at(e)

    details = {k: (v, s, e) for k, v, s, e in members(line, info[1])}
    severity = details.get("severity", ("",))[0]
    result = _Result(template_id=span(tid), stated=span(found.get("matcher-status") or tid),
                     type=span(found.get("type")) or ("", 0, 0), severity=severity if isinstance(severity, str) else "",
                     sub=found.get("matcher-name", found.get("extractor-name", ("",)))[0] or "",
                     target=span(found.get("matched-at")) or span(found.get("host")), ip=span(found.get("ip")),
                     port=span(found.get("port")), name=span(details.get("name")))
    host = span(found.get("host"))
    if host and re.search(r"[/:]", host[0]) and not _is_ip(host[0]):
        host = _split(host)[0]
    result.host = host or (_split(result.target)[0] if result.target else None)
    if result.port is None and result.target:
        result.port = _split(result.target)[1]
    for key in ("matcher-name", "extractor-name"):
        if found.get(key, ("",))[0]:
            result.ext[key] = found[key][0]
    for key in INFO_EXT:
        if details.get(key, (None,))[0]:
            result.ext[key] = details[key][0]
    classification = details.get("classification", ({},))[0]
    if isinstance(classification, dict):
        result.ext.update({k: classification[k] for k in CLASSIFICATION_EXT if classification.get(k)})
    for key in ("extracted-results", "meta"):
        if found.get(key, (None,))[0]:
            result.lists[key] = found[key][0] if key == "extracted-results" else [found[key][0]]
    return result


def _screen(shown: re.Match, at) -> _Result | None:
    if shown.group("status") == "failed":
        return None
    result = _Result(template_id=(shown.group("id"), at(shown.start("id")), at(shown.end("id"))),
                     stated=(shown.group("id"), at(shown.start("id")), at(shown.end("id"))),
                     type=(shown.group("type"), at(shown.start("type")), at(shown.end("type"))),
                     severity=shown.group("severity"), sub=shown.group("sub") or "",
                     target=(shown.group("target"), at(shown.start("target")), at(shown.end("target"))))
    result.host, result.port = _split(result.target)
    if result.host and _is_ip(result.host[0]):
        result.ip = result.host
    if shown.group("rest"):
        result.lists["shown"] = [shown.group("rest")]
    return result


def _split(target: Span) -> tuple[Span | None, Span | None]:
    """The host and the port written in a matched-at value (a URL, ``host:port`` or a bare host), as spans."""
    value, lo, _ = target
    try:
        parts = urlsplit(value if "://" in value else f"//{value}")
        host, port = parts.hostname, parts.port
    except ValueError:
        return None, None
    at = value.lower().find(host) if host else -1
    if at < 0:
        return None, None

    def part(i: int, text: str) -> Span:
        start = lo + len(value[:i].encode("utf-8"))
        return text, start, start + len(text.encode("utf-8"))

    found = part(at, value[at:at + len(host)])
    if port is None:
        return found, None
    i = value.find(f":{port}", at + len(host))
    return found, (None if i < 0 else part(i + 1, str(port)))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _records(r: _Result, raw: Input, held: dict[str, dict[str, Any]]) -> bool:
    """Write one result's host, service and finding into ``held``; False when its host is not yet known."""
    def ref(span: Span) -> dict[str, Any]:
        return cite(raw.blob, raw.data, span[1], span[2], TOOL, raw.source)

    finding = records.new("finding")
    title = r.template_id[0] + (f":{r.sub}" if r.sub else "") + (f" at {r.target[0]}" if r.target else "")
    records.set_field(finding, "title", title, ref(r.template_id))
    if r.name:
        records.set_field(finding, "description", r.name[0], ref(r.name))
    records.set_field(finding, "status", "confirmed", ref(r.stated))
    if r.type[0] != "dns" and (r.ip or r.host):
        host_id = _host(r, raw, held, ref)
        if host_id is None:
            return False
        records.set_field(finding, "host_id", host_id, ref(r.ip or r.host))
        if r.type[0] in SERVICE_TYPES and r.port and str(r.port[0]).isdigit():
            svc = records.new("service")
            records.set_field(svc, "host_id", host_id, ref(r.ip or r.host))
            records.set_field(svc, "port", int(r.port[0]), ref(r.port))
            records.set_field(svc, "protocol", "tcp", ref(r.type))
            sid = records.make_id(svc)
            held.setdefault(sid, svc)
            records.set_field(finding, "service_id", sid, ref(r.port))
    finding["ext"].update({"severity": r.severity, "template-id": r.template_id[0], "type": r.type[0]}, **r.ext)
    if r.target:
        finding["ext"]["matched-at"] = r.target[0]
    fid = records.make_id(finding)
    kept = held.setdefault(fid, finding)
    for key, values in r.lists.items():
        for value in values:
            records.add_to_ext_list(kept, key, value)
    return True


def _host(r: _Result, raw: Input, held: dict[str, dict[str, Any]], ref) -> str | None:
    """The id of the result's host, written into ``held``; None when it is named only by a name that no
    single held host carries."""
    if r.ip is None and r.host is not None and _is_ip(r.host[0]):
        r.ip = r.host
    name = r.host[0] if r.host and not _is_ip(r.host[0]) else None
    if r.ip is None:
        if name is None:
            return None
        named = [h for h in [*raw.known.values(), *held.values()]
                 if h["type"] == "host" and name.casefold() in {n.casefold() for n in h.get("hostnames") or []}]
        ids = {h["id"] if "id" in h else records.make_id(h) for h in named}
        return ids.pop() if len(ids) == 1 else None
    hid = f"host:{r.ip[0]}"
    host = held.get(hid)
    if host is None:
        host = held[hid] = records.new("host")
        records.set_field(host, "ip", r.ip[0], ref(r.ip))
    if name and name not in host.get("hostnames", []):
        records.set_field(host, "hostnames", host.get("hostnames", []) + [name],
                          host["prov"].get("hostnames", []) + [ref(r.host)])
    return hid
