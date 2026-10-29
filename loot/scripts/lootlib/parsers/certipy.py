"""certipy ``find`` output saved with -json, -text or -stdout: a finding per weakness certipy
flags on a CA or a template, on the one held host carrying the CA's DNS name. CA and template
settings and permissions are counted, not recorded."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from lootlib import records
from lootlib.parsers import WRAPPER, Input, ParserError, split_lines
from lootlib.prov import TOOL, cite

NAME = "certipy"
_JSON = re.compile(rb'\A\s*\{\s*"Certificate Authorities"\s*:\s*\{')
_TEXT = re.compile(rb"^Certificate Authorities\r?\n {2}\d+\r?\n {4}CA Name +: ", re.MULTILINE)
_FIELD = re.compile(r"^ +(?P<key>\S(?:.*?\S)?) +: (?P<value>.*?)\s*$")
_STATUS = re.compile(r"^(?:\[[*!+-]\] |Certipy v\S+ - by )")
_SECTIONS = {"Certificate Authorities": "ca", "Certificate Templates": "template"}
_VULNS = "[!] Vulnerabilities"
_DECODER = json.JSONDecoder()
_WS = re.compile(r"\s*")

Span = tuple[str, int, int]


@dataclass
class _Object:
    kind: str
    fields: dict[str, list[Span]] = field(default_factory=dict)
    vulns: list[tuple[Span, Span]] = field(default_factory=list)

    def first(self, key: str) -> Span | None:
        return (self.fields.get(key) or [None])[0]


def sniff(data: bytes, hint: str | None = None) -> bool:
    return bool(_JSON.match(data[:256]) or _TEXT.search(data))


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = raw.data.decode("utf-8")
        json_text = text if _JSON.match(raw.data[:256]) else None
        objects = list(_from_json(text) if json_text else _from_text(text, raw))
    except (UnicodeDecodeError, ValueError, IndexError) as err:
        raise ParserError(f"not certipy output Trove can read: {err}") from err
    cas = {o.first("CA Name")[0]: o for o in objects if o.kind == "ca" and o.first("CA Name")}
    hosts = [r for r in raw.known.values() if r["type"] == "host"]
    out: list[dict[str, Any]] = []
    waiting: dict[str, int] = {}
    several: dict[str, int] = {}
    for obj in objects:
        for ca_name in _published_by(obj):
            ca = cas.get(ca_name[0])
            dns = ca.first("DNS Name") if ca else None
            if dns is None:
                continue
            named = _hosts(hosts, dns[0])
            if len(named) != 1:
                held = several if named else waiting
                held[dns[0]] = len(named)
                continue
            out += [_finding(raw, json_text, obj, ca_name[0], esc, reason, named[0], dns) for esc, reason in obj.vulns]
    templates = sum(o.kind == "template" for o in objects)
    raw.notices.append(f"{raw.source}: {len(cas)} CA(s) and {templates} template(s); only the weaknesses "
                       "certipy flags are recorded, not their settings or permissions. The file is in raw/ verbatim.")
    if waiting:
        raw.unresolved.append("host")
        raw.notices.append(f"{raw.source}: the weaknesses on {', '.join(sorted(waiting))} wait for a scan that "
                           "names the CA's host; each lands on that host once Trove holds it.")
    for dns, count in sorted(several.items()):
        raw.notices.append(f"{raw.source}: the CA name {dns} matches {count} held hosts, so its weaknesses "
                           "were not recorded. The file is in raw/ verbatim.")
    return out


def _published_by(obj: _Object) -> list[Span]:
    """The CA names an object's weaknesses belong to: its own, or the CAs publishing a template."""
    if not obj.vulns:
        return []
    return obj.fields.get("CA Name" if obj.kind == "ca" else "Certificate Authorities") or []


def _hosts(hosts: list[dict[str, Any]], dns: str) -> list[dict[str, Any]]:
    """The held hosts carrying the DNS name, or else its first label."""
    want = dns.casefold()
    for name in (want, want.split(".")[0]):
        named = [h for h in hosts if name in {n.casefold() for n in h.get("hostnames") or []}]
        if named:
            return named
    return []


def _finding(raw: Input, text: str | None, obj: _Object, ca: str, esc: Span, reason: Span,
             host: dict[str, Any], dns: Span) -> dict[str, Any]:
    title = f"{esc[0]}: {ca}" if obj.kind == "ca" else f"{esc[0]}: template {obj.first('Template Name')[0]} on {ca}"
    rec = records.new("finding")
    records.set_field(rec, "title", title, _ref(raw, text, esc))
    records.set_field(rec, "description", reason[0], _ref(raw, text, reason))
    records.set_field(rec, "host_id", records.make_id(host), _ref(raw, text, dns))
    records.set_field(rec, "status", "confirmed", _ref(raw, text, esc))
    return rec


def _ref(raw: Input, text: str | None, span: Span) -> dict[str, Any]:
    """A span's citation: character offsets into ``text``, or byte offsets when there is no text."""
    if text is None:
        return cite(raw.blob, raw.data, span[1], span[2], TOOL, raw.source)
    lo = len(text[:span[1]].encode("utf-8"))
    return cite(raw.blob, raw.data, lo, lo + len(text[span[1]:span[2]].encode("utf-8")), TOOL, raw.source)


def _from_json(text: str) -> Iterator[_Object]:
    for section, _, value, start, _ in _members(text, text.index("{")):
        kind = _SECTIONS.get(section)
        if kind is None or not isinstance(value, dict):
            continue
        for _, _, _, at, _ in _members(text, start):
            obj = _Object(kind)
            for key, _, body, vs, ve in _members(text, at):
                if key == _VULNS and isinstance(body, dict):
                    obj.vulns = [((k, ks[0], ks[1]), (v, s + 1, e - 1))
                                 for k, ks, v, s, e in _members(text, vs) if isinstance(v, str)]
                elif isinstance(body, str):
                    obj.fields[key] = [(body, vs + 1, ve - 1)]
                elif isinstance(body, list):
                    obj.fields[key] = [(v, s + 1, e - 1) for v, s, e in _items(text, vs) if isinstance(v, str)]
            yield obj


def _members(text: str, at: int) -> Iterator[tuple[str, tuple[int, int], Any, int, int]]:
    """Each member of the JSON object whose ``{`` is at ``at``: key, key span, value, value span."""
    at = _WS.match(text, at + 1).end()
    while text[at] != "}":
        key, key_end = _DECODER.raw_decode(text, at)
        start = _WS.match(text, _WS.match(text, key_end).end() + 1).end()
        value, end = _DECODER.raw_decode(text, start)
        yield key, (at + 1, key_end - 1), value, start, end
        at = _WS.match(text, end).end()
        at = _WS.match(text, at + 1).end() if text[at] == "," else at


def _items(text: str, at: int) -> Iterator[tuple[Any, int, int]]:
    at = _WS.match(text, at + 1).end()
    while text[at] != "]":
        value, end = _DECODER.raw_decode(text, at)
        yield value, at, end
        at = _WS.match(text, end).end()
        at = _WS.match(text, at + 1).end() if text[at] == "," else at


def _from_text(text: str, raw: Input) -> list[_Object]:
    """Objects from certipy's indented text, spans in bytes; lines outside it that are not its status
    go to ``unread``."""
    objects: list[_Object] = []
    kind, obj, in_vulns, last, column = None, None, False, None, 0
    for body, start in split_lines(text):
        def at(i: int) -> int:
            return start + len(body[:i].encode("utf-8"))

        indent = len(body) - len(body.lstrip(" "))
        if not body.strip():
            continue
        if indent == 0:
            if _STATUS.match(body) or WRAPPER.match(body):
                continue
            kind, obj = _SECTIONS.get(body.strip()), None
            if kind is None:
                raw.unread.append(body)
            continue
        if kind is None:
            raw.unread.append(body)
            continue
        if indent == 2 and body.strip().isdigit():
            obj, in_vulns, last = _Object(kind), False, None
            objects.append(obj)
            continue
        if obj is None:
            continue
        if indent == 4:
            in_vulns, last = body.strip() == _VULNS, None
        found = _FIELD.match(body)
        if found:
            key = (found["key"], at(found.start("key")), at(found.end("key")))
            value = (found["value"], at(found.start("value")), at(found.end("value")))
            if in_vulns and indent == 6:
                obj.vulns.append((key, value))
            elif indent == 4:
                obj.fields[key[0]] = last = [value]
                column = found.start("value")
        elif last is not None and indent == column:
            last.append((body.strip(), at(indent), at(len(body.rstrip()))))
    return objects
