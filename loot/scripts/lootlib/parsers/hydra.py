"""Hydra's ``-o`` file, its ``-b json`` file and console captures to hosts, services and confirmed logins.

Several passwords for one login on one host and port make no credential, and a found line with no
login or no password is only reported. Hydra's own lines never go to extraction."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from lootlib import records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError, creds
from lootlib.prov import TOOL, YOU, cite

NAME = "hydra"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
HEADER = re.compile(r"^# Hydra \S+ run at \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} on .* \(.*\)$")
FOUND = re.compile(r"^\[(?P<port>\d{1,5})\]\[(?P<service>[\w-]+)\] host: (?P<host>\S+)(?:   misc: .*?)?"
                   r"(?:   login: (?P<login>.*?))?(?:   password: (?P<password>.*))?$")
RESULT = re.compile(r'^\t\{"port": (?P<port>\d{1,5}), "service": "(?P<service>[\w-]+)", "host": "(?P<host>[^"]+)", '
                    r'"login": "(?P<login>(?:[^"\\]|\\.)*)", "password": "(?P<password>(?:[^"\\]|\\.)*)"\},?$')
COMMANDLINE = re.compile(r'^\t"commandline": ".*"$')
BANNER = re.compile(r"^Hydra \S+ \(c\) \d{4} by van Hauser/THC|^Hydra \(https://github\.com/vanhauser-thc/thc-hydra\) "
                    r"starting at |^\t\"software\": \"Hydra\", ")
OWN = re.compile(r"^(?:Hydra \S+ \(c\) |Hydra \(\S+\) (?:starting|finished) at |"
                 r"\[(?:DATA|STATUS|(?:RE-|REDO-)?ATTEMPT|ATTEMPT-ERROR|INFO|INFORMATION|WARNING|ERROR|VERBOSE|DEBUG|"
                 r"DEBUG-ERROR)\] |\d+ of \d+ targets? (?:successfully )?completed, \d+ valid passwords? found$)")
FRAME = re.compile(r'^(?:\{ "generator": \{|\t"(?:software|server)": .*|\t\},|"results": \[|\t\],|'
                   r'"success": (?:true|false),|"errormessages": \[.*\],|"quantityfound": \d+ *\})$')
UDP = {"icq", "pcnfs", "sip", "snmp", "teamspeak"}
FIELDS = ("port", "service", "host", "login", "password")


@dataclass
class _Found:
    line: creds.Line
    values: dict[str, str]
    spans: dict[str, tuple[int, int]] = field(default_factory=dict)
    first: int = 0

    def ref(self, raw: Input, name: str, through: str | None = None) -> dict[str, Any]:
        start, end = self.spans[name][0], self.spans[through or name][1]
        return cite(raw.blob, raw.data, self.line.at(start), self.line.at(end), TOOL, raw.source)

    def whole(self, raw: Input) -> dict[str, Any]:
        return cite(raw.blob, raw.data, self.line.at(self.first), self.line.at(self.spans["password"][1]),
                    TOOL, raw.source)


def sniff(data: bytes, hint: str | None = None) -> bool:
    try:
        text = data[:WINDOW].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return any(BANNER.match(line.text) or HEADER.match(line.text) or RESULT.match(line.text)
               or FOUND.match(ANSI.sub("", line.text)) for line in creds.lines(text))


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    found: list[_Found] = []
    commands: list[str] = []
    for line in creds.lines(text):
        bare = ANSI.sub("", line.text)
        if HEADER.match(bare) or COMMANDLINE.match(line.text):
            commands.append(line.text)
            raw.unread.append(line.text)
            continue
        hit = _found_in(line, bare)
        if hit is not None:
            found.append(hit)
        elif bare.strip() and not (OWN.match(bare) or FRAME.match(line.text) or WRAPPER.match(line.text)):
            raw.unread.append(line.text)

    passwords: dict[tuple[str, str, str, str], set[str]] = {}
    for hit in found:
        if hit.values.get("login") and hit.values.get("password"):
            passwords.setdefault(_group(hit), set()).add(hit.values["password"])
    held: dict[str, dict[str, Any]] = {}
    waiting: set[str] = set()
    partial = 0
    for hit in found:
        host_id = _host(hit, raw, held)
        if host_id is None:
            waiting.add(hit.values["host"])
        else:
            _service(hit, host_id, raw, held)
        if not (hit.values.get("login") and hit.values.get("password")):
            partial += 1
        elif len(passwords[_group(hit)]) == 1:
            rec = _credential(hit, host_id, raw)
            rid = records.make_id(rec)
            if rid in held:
                records.merge(held[rid], rec)
            held.setdefault(rid, rec)

    if commands and found:
        raw.unread[:] = [kept for kept in raw.unread if kept not in commands]
        raw.notices.append(f"{len(commands)} Hydra command line(s) not sent for extraction: the found lines in "
                           "this file already hold the logins that worked.")
    for (host, port, service, login), tried in passwords.items():
        if len(tried) > 1:
            raw.notices.append(
                f"{login} on {host}:{port} ({service}): Hydra printed {len(tried)} passwords for one login on one "
                "port, the sign of a false positive (a wrong failure string, or a server that takes any password). "
                "No credential was made; the lines are in raw/ verbatim.")
    if partial:
        raw.notices.append(f"{partial} found line(s) named no login or no password (VNC, Redis and SNMP have no "
                           "login; an empty password prints none), so no credential was made from them. "
                           "The lines are in raw/ verbatim.")
    if waiting:
        raw.unresolved.append("host")
        raw.notices.append(f"the logins on {', '.join(sorted(waiting))} name a host Trove does not hold by that name. "
                           "They are stored with no hosts and gain the host once a scan that names it is imported.")
    return list(held.values())


def _found_in(line: creds.Line, bare: str) -> _Found | None:
    """A found line from the text file, the console or the JSON file, with each value's span in ``line``."""
    result = RESULT.match(line.text)
    if result is not None:
        hit = _Found(line, {k: result.group(k).replace('\\"', '"') for k in FIELDS})
        hit.spans = {k: result.span(k) for k in FIELDS}
        hit.first = 1
        return hit
    match = FOUND.match(bare)
    if match is None:
        return None
    hit = _Found(line, {k: match.group(k) for k in FIELDS if match.group(k) is not None})
    at = 0
    for name in FIELDS:
        if name not in hit.values:
            continue
        if name in ("host", "login", "password"):
            at = line.text.index(f"{'' if name == 'host' else '   '}{name}: ", at)
        start = line.text.index(hit.values[name], at)
        at = start + len(hit.values[name])
        hit.spans[name] = (start, at)
    return hit


def _group(hit: _Found) -> tuple[str, str, str, str]:
    v = hit.values
    return v["host"].casefold(), v["port"], v["service"], v["login"]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _host(hit: _Found, raw: Input, held: dict[str, dict[str, Any]]) -> str | None:
    """The id of the host the line names: its IP, or the one held host carrying that name; None otherwise."""
    name = hit.values["host"]
    if _is_ip(name):
        hid = f"host:{name}"
        if hid not in held:
            held[hid] = records.new("host")
            records.set_field(held[hid], "ip", name, hit.ref(raw, "host"))
        return hid
    named = {h.get("id") or records.make_id(h) for h in [*raw.known.values(), *held.values()]
             if h["type"] == "host" and name.casefold() in {n.casefold() for n in h.get("hostnames") or []}}
    return named.pop() if len(named) == 1 else None


def _service(hit: _Found, host_id: str, raw: Input, held: dict[str, dict[str, Any]]) -> None:
    """The port Hydra attacked; the module name is its name unless a scan already named it."""
    svc = records.new("service")
    records.set_field(svc, "host_id", host_id, hit.ref(raw, "host"))
    records.set_field(svc, "port", int(hit.values["port"]), hit.ref(raw, "port"))
    module = hit.values["service"]
    records.set_field(svc, "protocol", "udp" if module in UDP else "tcp", hit.ref(raw, "service"))
    sid = records.make_id(svc)
    if not (raw.known.get(sid) or {}).get("name"):
        records.set_field(svc, "name", module, hit.ref(raw, "service"))
    held.setdefault(sid, svc)


def _credential(hit: _Found, host_id: str | None, raw: Input) -> dict[str, Any]:
    """A login Hydra reported once for its host and port: confirmed, on that host when Trove holds it."""
    login = hit.values["login"]
    rec = records.new("credential")
    records.set_field(rec, "principal", login, hit.ref(raw, "login"))
    if raw.realm and "\\" not in login and "@" not in login:
        records.set_field(rec, "realm", raw.realm, {"blob": raw.blob, "origin": YOU, "source": "--realm",
                                                    "quote": raw.realm})
    records.set_field(rec, "secret", hit.values["password"], hit.ref(raw, "password"))
    records.set_field(rec, "state", "confirmed", hit.whole(raw))
    if host_id is not None:
        records.set_field(rec, "hosts", [host_id], [hit.ref(raw, "host", through="password")])
    return rec
