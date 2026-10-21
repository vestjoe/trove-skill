"""nmap ``-oN`` and ``-oG`` text to hosts and services, every field cited.

The version column is kept whole as ``banner``: splitting it into product and
version would be a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from lootlib import records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError
from lootlib.prov import TOOL, cite

NAME = "nmap-text"
IP = r"\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39}"
PROTOCOLS = ("tcp", "udp", "sctp", "ip")

REPORT = re.compile(rf"^Nmap scan report for (?:(?P<hostname>\S+) \((?P<ip>{IP})\)|(?P<bare>{IP}) *$)")
HOST_STATE = re.compile(r"^Host is (?P<state>up|down)\b")
PORT_ROW = re.compile(
    r"^(?P<port>\d{1,5})/(?P<protocol>tcp|udp|sctp|ip) +(?P<state>\S+) +"
    r"(?P<service>\S+)(?: +(?P<banner>\S.*?))? *$"
)
GREP_HOST = re.compile(rf"^Host: (?P<ip>{IP}) \((?P<hostname>[^)]*)\)")
GREP_STATUS = re.compile(r"^Status: (?P<state>[A-Za-z]+)")
PORTS_FIELD = "Ports: "
ENTRY_START = re.compile(r"(?:^|, )(?=\d{1,5}/)")
ENTRY_FIELDS = ("port", "state", "protocol", "owner", "service", "rpc", "banner")
NMAP_LINE = re.compile(
    r"^(?:# Nmap |# Ports scanned: |\|(?:_|\s+\S)(?!.*\|\s*$)|SF[:-]|Nmap scan report for \S+(?: \([^)]*\))? *$|Nmap done: "
    r"|Starting Nmap |Host is (?:up|down)\b|Host script results:"
    r"|Not shown: |All \d+ scanned ports|Some closed ports|PORT +STATE|Other addresses for |rDNS record for "
    r"|Service Info: (?:Host|OS|Device|CPE)s?: |Service detection performed|MAC Address: |Device type: "
    r"|Running(?: \(JUST GUESSING\))?: "
    r"|OS (?:details|CPE|fingerprint not ideal|and Service detection)|Aggressive OS guesses|No exact OS matches"
    r"|Network Distance: |TRACEROUTE|HOP RTT|Warning: OSScan|Read data files from|Uptime guess: "
    r"|TCP Sequence Prediction|IP ID Sequence|TCP/IP fingerprint|Too many fingerprints|=+NEXT SERVICE FINGERPRINT"
    r"|Initiating .* at \d\d:\d\d|Scanning \S+ [(\[]|Scanning \d+ (?:hosts|services)|Completed .* at \d\d:\d\d"
    r"|Discovered open port \d+/|Stats: |NSE: |Raw packets sent"
    r"|\d+ services? unrecognized despite|(?:Pre|Post)-scan script results:"
    r"|\d+ +[\d.]+ ms |\d+/(?:tcp|udp|sctp|ip) "
    r"|Scanned (?:at .* )?for \d+s$|Final times for host: |Increasing send delay for |Warning: \S+ giving up on port "
    r"|OS:|OS detection performed|(?:Initiating|Retrying) OS detection |.+ Timing: About [\d.]+% done"
    r"|Read from \S+: |Overall sending rates: |mass_dns: |-+ Timing report -+$|-{45}$"
    r"|  (?:hostgroups|rtt-timeouts|max-scan-delay|parallelism|max-retries|min-rate): | +Raw packets sent: )")


@dataclass(frozen=True)
class _Line:
    text: str
    start: int

    def at(self, index: int) -> int:
        return self.start + len(self.text[:index].encode("utf-8"))


@dataclass(frozen=True)
class _Port:
    port: int
    port_text: str
    port_at: int
    protocol: str
    protocol_at: int
    state: str
    state_at: int
    name: str
    name_at: int
    tunnel: str
    banner: str
    banner_at: int


def sniff(data: bytes, hint: str | None = None) -> bool:
    text = data[:WINDOW].decode("utf-8", errors="replace")
    return any(REPORT.match(line) or GREP_HOST.match(line) for line in text.splitlines())


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    held: dict[str, dict[str, Any]] = {}
    unread: list[str] = []
    current = None
    for line in _lines(text):
        grepable = GREP_HOST.match(line.text)
        if grepable is not None:
            _grepable_host(grepable, line, raw, held, unread)
            current = None
            continue
        report = REPORT.match(line.text)
        if report is not None:
            bare = report.group("bare")
            current = (_host(bare, report.start("bare"), "", 0, line, raw, held) if bare is not None else
                       _host(report.group("ip"), report.start("ip"), report.group("hostname"),
                             report.start("hostname"), line, raw, held))
            continue
        if current is None:
            _unread(line, raw)
            continue
        state = HOST_STATE.match(line.text)
        if state is not None:
            _set_state(current, state.group("state"), line, state.start("state"), raw)
            continue
        row = PORT_ROW.match(line.text)
        if row is not None:
            _add_service(_row_port(row), current, line, raw, held)
        else:
            _unread(line, raw)
    if unread:
        raw.notices.append(
            f"{len(unread)} port entr(y/ies) did not state one of {', '.join(PROTOCOLS)} and were not read "
            f"({', '.join(unread[:3])}{', …' if len(unread) > 3 else ''}). The lines are in raw/ verbatim.")
    return list(held.values())


def _unread(line: _Line, raw: Input) -> None:
    if line.text.strip() and not NMAP_LINE.match(line.text) and not WRAPPER.match(line.text):
        raw.unread.append(line.text)


def _lines(text: str) -> list[_Line]:
    lines, offset = [], 0
    for raw_line in text.splitlines(keepends=True):
        lines.append(_Line(raw_line.rstrip("\r\n"), offset))
        offset += len(raw_line.encode("utf-8"))
    return lines


def _cite(raw: Input, line: _Line, start: int, value: str) -> dict[str, Any]:
    return cite(raw.blob, raw.data, line.at(start), line.at(start + len(value)), TOOL, raw.source)


def _host(ip: str, ip_at: int, hostname: str, hostname_at: int, line: _Line,
          raw: Input, held: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The record for this address, made once: grepable output states a host twice."""
    if f"host:{ip}" in held:
        return held[f"host:{ip}"]
    host = records.new("host")
    records.set_field(host, "ip", ip, _cite(raw, line, ip_at, ip))
    if hostname:
        records.set_field(host, "hostnames", [hostname], [_cite(raw, line, hostname_at, hostname)])
    held[f"host:{ip}"] = host
    return host


def _grepable_host(match: "re.Match[str]", line: _Line, raw: Input,
                   held: dict[str, dict[str, Any]], unread: list[str]) -> None:
    host = _host(match.group("ip"), match.start("ip"), match.group("hostname"),
                 match.start("hostname"), line, raw, held)
    at = match.end()
    for field in line.text[at:].split("\t"):
        at += len(field) + 1
        start = at - len(field) - 1
        status = GREP_STATUS.match(field)
        if status is not None:
            _set_state(host, status.group("state"), line, start + status.start("state"), raw)
        elif field.startswith(PORTS_FIELD):
            for offset, entry in _entries(field[len(PORTS_FIELD):]):
                found = _entry_port(entry, start + len(PORTS_FIELD) + offset)
                if found is None:
                    unread.append(" ".join(entry.split())[:48])
                else:
                    _add_service(found, host, line, raw, held)


def _entries(value: str):
    """Each ``Ports:`` entry; ``, `` separates only where a port number follows it."""
    starts = [found.end() for found in ENTRY_START.finditer(value)]
    for index, start in enumerate(starts):
        end = starts[index + 1] - 2 if index + 1 < len(starts) else len(value)
        yield start, value[start:end]


def _entry_port(entry: str, at: int) -> _Port | None:
    """One ``port/state/protocol/owner/service/rpc/version/`` entry, split, not matched."""
    fields = entry.split("/")
    if len(fields) < 3 or not fields[0].isdigit():
        return None
    offsets, running = {}, at
    for name, field in zip(ENTRY_FIELDS, fields):
        offsets[name] = running
        running += len(field) + 1
    parts = dict(zip(ENTRY_FIELDS, fields))
    if parts.get("protocol", "") not in PROTOCOLS:
        return None
    tunnel, name, name_at = _split_service(parts.get("service", ""), offsets.get("service", 0), "|")
    return _Port(int(parts["port"]), parts["port"], offsets["port"], parts["protocol"], offsets["protocol"],
                 parts.get("state", ""), offsets.get("state", 0), name, name_at, tunnel,
                 parts.get("banner", ""), offsets.get("banner", 0))


def _row_port(row: "re.Match[str]") -> _Port:
    tunnel, name, name_at = _split_service(row.group("service"), row.start("service"), "/")
    banner = row.group("banner") or ""
    return _Port(int(row.group("port")), row.group("port"), row.start("port"), row.group("protocol"),
                 row.start("protocol"), row.group("state"), row.start("state"), name, name_at, tunnel,
                 banner, row.start("banner") if banner else 0)


def _split_service(text: str, at: int, separator: str) -> tuple[str, str, int]:
    """``ssl/http?`` to the tunnel, the name and where the name sits."""
    tunnel = ""
    head, found, tail = text.partition(separator)
    if found:
        tunnel, text, at = head, tail, at + len(head) + 1
    return tunnel, text.removesuffix("?"), at


def _add_service(found: _Port, host: dict[str, Any], line: _Line, raw: Input,
                 held: dict[str, dict[str, Any]]) -> None:
    svc = records.new("service")
    records.set_field(svc, "host_id", f"host:{host['ip']}", host["prov"]["ip"])
    records.set_field(svc, "port", found.port, _cite(raw, line, found.port_at, found.port_text))
    records.set_field(svc, "protocol", found.protocol, _cite(raw, line, found.protocol_at, found.protocol))
    for name, value, at in (("state", found.state, found.state_at), ("name", found.name, found.name_at),
                            ("banner", found.banner, found.banner_at)):
        if value:
            records.set_field(svc, name, value, _cite(raw, line, at, value))
    if found.tunnel:
        svc["ext"]["tunnel"] = found.tunnel
    held.setdefault(records.make_id(svc), svc)


def _set_state(host: dict[str, Any], state: str, line: _Line, at: int, raw: Input) -> None:
    """Stored lowercase, quoting the spelling the format used."""
    if "state" not in host:
        records.set_field(host, "state", state.lower(), _cite(raw, line, at, state))
