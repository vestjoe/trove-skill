"""BloodHound collector JSON (v6), reduced: users, groups and computers as principals,
memberships, a computer's OS onto the one host carrying its name, and passwords a
description states. Domains, OUs, GPOs, containers and access rules are counted, not
recorded."""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

from lootlib import records
from lootlib.parsers import Input, ParserError
from lootlib.prov import TOOL, cite

NAME = "bloodhound"
_HEAD = re.compile(rb'\A\s*\{\s*"data"\s*:\s*\[')
_META = re.compile(rb'"meta"\s*:\s*\{[^{}]*"type"\s*:\s*"(?P<type>[a-z]+)"')
_READ = ("users", "groups", "computers")
ROASTS = (("dontreqpreauth", "AS-REP roastable"), ("hasspn", "Kerberoastable"))
_STATED = re.compile(r"\bpassword\s*[:=]\s*(?P<value>\S+)", re.IGNORECASE)


def sniff(data: bytes, hint: str | None = None) -> bool:
    return bool(_HEAD.match(data[:64])) and _META.search(data[-1024:]) is not None


def parse(raw: Input) -> list[dict[str, Any]]:
    meta = _META.search(raw.data[-1024:])
    try:
        text = raw.data.decode("utf-8")
        elements = list(_elements(text))
    except (UnicodeDecodeError, ValueError, IndexError) as err:
        raise ParserError(f"not BloodHound JSON Trove can read: {err}") from err
    kind = meta.group("type").decode() if meta else ""
    if kind not in _READ:
        raw.notices.append(f"{raw.source}: {len(elements)} {kind or 'objects'}; Trove has no record type "
                           "for these. The file is in raw/ verbatim.")
        return []
    citer = _Citer(raw, text)
    rules = sum(len(e.body.get("Aces") or []) for e in elements)
    if rules:
        raw.notices.append(f"{raw.source}: {rules} access rule(s) were not recorded; Trove has no record "
                           "type for who may act on what. The file is in raw/ verbatim.")
    if kind == "users":
        bare = sum(1 for e in elements if not e.props.get("samaccountname")
                   and str(e.body.get("ObjectIdentifier", "")).startswith("S-1-5-21-"))
        if bare:
            raw.notices.append(f"{raw.source}: {bare} user(s) have no samaccountname, so no account was made "
                               "from them. The collector ran without object properties; collect with -c All. "
                               "The file is in raw/ verbatim.")
        return [r for e in elements for r in _account(e, citer) + _roastable(e, citer)]
    if kind == "computers":
        return _computers(elements, citer, raw)
    return _groups(elements, citer, raw)


class _Element:
    def __init__(self, body: dict[str, Any], start: int, end: int) -> None:
        self.body, self.start, self.end = body, start, end

    @property
    def props(self) -> dict[str, Any]:
        return self.body.get("Properties") or {}


def _elements(text: str) -> Iterator[_Element]:
    decoder = json.JSONDecoder()
    at = text.index("[", text.index('"data"')) + 1
    while True:
        while text[at] in " \t\r\n,":
            at += 1
        if text[at] == "]":
            return
        body, end = decoder.raw_decode(text, at)
        yield _Element(body, at, end)
        at = end


class _Citer:
    """Byte spans for values found inside one element's text."""

    def __init__(self, raw: Input, text: str) -> None:
        self.raw, self.text = raw, text

    def value(self, element: _Element, key: str, value: str, after: int = 0) -> tuple[dict[str, Any], int]:
        """Cite ``value`` where it follows ``key`` in this element; returns the ref and its end offset."""
        at = self.text.index(json.dumps(key), element.start + after, element.end)
        quoted = json.dumps(value, ensure_ascii=False)
        at = self.text.index(quoted, at, element.end) + 1
        return self._span(at, at + len(quoted) - 2), at + len(quoted) - 1 - element.start

    def inside(self, element: _Element, key: str, whole: str, part: str) -> dict[str, Any]:
        """Cite ``part`` where it sits inside the string value ``whole`` of ``key``."""
        _, end = self.value(element, key, whole)
        start = element.start + end - len(json.dumps(whole, ensure_ascii=False)) + 1
        at = self.text.index(json.dumps(part, ensure_ascii=False)[1:-1], start, element.start + end)
        return self._span(at, at + len(json.dumps(part, ensure_ascii=False)) - 2)

    def key(self, element: _Element, key: str) -> dict[str, Any]:
        at = self.text.index(json.dumps(key), element.start, element.end) + 1
        return self._span(at, at + len(key))

    def true(self, element: _Element, key: str) -> dict[str, Any]:
        """Cite ``"key": true`` in this element."""
        at = self.text.index(json.dumps(key), element.start, element.end)
        return self._span(at, self.text.index("true", at, element.end) + 4)

    def _span(self, start: int, end: int) -> dict[str, Any]:
        lo = len(self.text[:start].encode("utf-8"))
        hi = lo + len(self.text[start:end].encode("utf-8"))
        return cite(self.raw.blob, self.raw.data, lo, hi, TOOL, self.raw.source)


def _principal(element: _Element, citer: _Citer) -> dict[str, Any] | None:
    sam, domain = element.props.get("samaccountname"), element.props.get("domain")
    sid = element.body.get("ObjectIdentifier")
    if not sam or not sid:
        return None
    rec = records.new("principal")
    records.set_field(rec, "principal", sam, citer.value(element, "samaccountname", sam)[0])
    records.set_field(rec, "sid", sid, citer.value(element, "ObjectIdentifier", sid)[0])
    if domain:
        records.set_field(rec, "realm", domain, citer.value(element, "domain", domain)[0])
    return rec


def _account(element: _Element, citer: _Citer) -> list[dict[str, Any]]:
    """A principal, plus a credential when its description states a password."""
    principal = _principal(element, citer)
    if principal is None:
        return []
    stated = _stated_password(element.props.get("description") or "")
    if stated is None:
        return [principal]
    cred = records.new("credential")
    for name in ("principal", "realm"):
        if name in principal["prov"]:
            records.set_field(cred, name, principal[name], principal["prov"][name])
    said = citer.inside(element, "description", element.props["description"], stated)
    records.set_field(cred, "secret", stated, said)
    records.set_field(cred, "state", "found", said)
    return [principal, cred]


def _roastable(element: _Element, citer: _Citer) -> list[dict[str, Any]]:
    """A finding per roast an enabled account is open to: no pre-auth, or an SPN."""
    props, out = element.props, []
    if props.get("enabled") is False or not props.get("samaccountname"):
        return out
    account = f"{props['domain']}\\{props['samaccountname']}" if props.get("domain") else props["samaccountname"]
    for flag, title in ROASTS:
        if props.get(flag) is True:
            stated = citer.true(element, flag)
            rec = records.new("finding")
            records.set_field(rec, "title", f"{title}: {account}", stated)
            records.set_field(rec, "status", "confirmed", stated)
            out.append(rec)
    return out


def _stated_password(description: str) -> str | None:
    """The value after ``password:`` or ``password =``, less a bracket the description opened."""
    match = _STATED.search(description)
    if match is None:
        return None
    value = match.group("value")
    if value.endswith(")") and description[:match.start()].count("(") > description[:match.start()].count(")"):
        value = value[:-1]
    return value or None


def _group(element: _Element, citer: _Citer) -> dict[str, Any] | None:
    """A group named by ``samaccountname``, or without one by ``name`` less its ``@DOMAIN``."""
    props, sid = element.props, element.body.get("ObjectIdentifier")
    dn, sam, full = props.get("distinguishedname"), props.get("samaccountname"), props.get("name")
    name = sam or (full or "").rpartition("@")[0] or full
    if not dn or not name or not sid:
        return None
    rec = records.new("group")
    records.set_field(rec, "name", name, citer.value(element, "samaccountname", sam)[0] if sam
                      else citer.inside(element, "name", full, name))
    records.set_field(rec, "dn", dn, citer.value(element, "distinguishedname", dn)[0])
    records.set_field(rec, "sid", sid, citer.value(element, "ObjectIdentifier", sid)[0])
    if props.get("domain"):
        records.set_field(rec, "realm", props["domain"], citer.value(element, "domain", props["domain"])[0])
    return rec


def _groups(elements: list[_Element], citer: _Citer, raw: Input) -> list[dict[str, Any]]:
    """Groups and their member_of edges; a member is resolved by SID against what is held."""
    by_sid = {r["sid"]: r for r in raw.known.values() if r.get("sid")}
    out: list[dict[str, Any]] = []
    unnamed: list[str] = []
    unresolved: dict[str, int] = {}
    for element in elements:
        group = _group(element, citer)
        if group is None:
            unnamed.append(str(element.props.get("name") or element.body.get("ObjectIdentifier")))
            continue
        out.append(group)
        after = (citer.text.index('"Members"', element.start, element.end) - element.start
                 if element.body.get("Members") else 0)
        for member in element.body.get("Members") or []:
            sid = member.get("ObjectIdentifier", "")
            ref, after = citer.value(element, "ObjectIdentifier", sid, after) if sid else (None, after)
            held = by_sid.get(sid)
            if held is None or ref is None:
                kind = member.get("ObjectType") or "unknown"
                unresolved[kind] = unresolved.get(kind, 0) + 1
                continue
            edge = records.new("relationship")
            records.set_field(edge, "src_id", held["id"], ref)
            records.set_field(edge, "kind", "member_of", citer.key(element, "Members"))
            records.set_field(edge, "dst_id", records.make_id(group), group["prov"]["sid"])
            out.append(edge)
    if unnamed:
        raw.notices.append(f"{raw.source}: {len(unnamed)} group(s) have no distinguished name and were not "
                           f"recorded ({', '.join(unnamed[:4])}{', …' if len(unnamed) > 4 else ''}).")
    if unresolved:
        raw.unresolved.extend(unresolved)
        counts = ", ".join(f"{n} {k.lower()}" for k, n in sorted(unresolved.items()))
        raw.notices.append(f"{raw.source}: {sum(unresolved.values())} membership(s) name a member Trove does "
                           f"not hold ({counts}). Import the file that names them and these resolve.")
    return out


def _computers(elements: list[_Element], citer: _Citer, raw: Input) -> list[dict[str, Any]]:
    """Each computer is a principal; its OS lands on the one held host that carries its name."""
    hosts = [r for r in raw.known.values() if r["type"] == "host"]
    out: list[dict[str, Any]] = []
    unmatched: list[str] = []
    for element in elements:
        out.extend(_account(element, citer))
        name, os_name = element.props.get("name"), element.props.get("operatingsystem")
        if not name or not os_name:
            continue
        named = [h for h in hosts if name.casefold() in {n.casefold() for n in h.get("hostnames") or []}]
        if len(named) != 1:
            unmatched.append(f"{name} ({len(named)} hosts carry it)" if named else name)
            continue
        host = records.new("host")
        records.set_field(host, "ip", named[0]["ip"], named[0]["prov"]["ip"])
        records.set_field(host, "os", os_name, citer.value(element, "operatingsystem", os_name)[0])
        out.append(host)
    if unmatched:
        raw.unresolved.append("host")
        raw.notices.append(f"{raw.source}: {len(unmatched)} computer(s) match no single host Trove holds by name "
                           f"({', '.join(unmatched[:4])}{', …' if len(unmatched) > 4 else ''}). Each is recorded "
                           "as a principal; its OS waits for a scan that names the host.")
    return out
