"""kerbrute's console captures and ``-o`` file to principals and confirmed Kerberos logins.

``VALID USERNAME`` is a principal, ``VALID LOGIN`` (also ``WITH ERROR``) a confirmed credential, and a
dumped AS-REP hash the credential ``creds`` makes from it. Nothing gets a host: a Kerberos login is the
realm's, not the KDC's. kerbrute's own lines never go to extraction."""

from __future__ import annotations

import re
from typing import Any

from lootlib import records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError, creds, hashformats
from lootlib.prov import TOOL, cite

NAME = "kerbrute"
LEAD = re.compile(r"^(?:\x1b\[[0-9;]*m)*")
TRAIL = re.compile(r"(?:\x1b\[[0-9;]*m)*$")
LOGGED = r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} >  "
OWN = re.compile(LOGGED)
KNOWN = re.compile(LOGGED + r"(?:Using KDC\(s\):$|\[\+\] VALID (?:USERNAME|LOGIN)|Done! Tested \d+ (?:usernames|logins) )")
USERNAME = re.compile(LOGGED + r"(?P<line>\[\+\] VALID USERNAME:\t (?P<name>[^@\s]+@\S+))$")
LOGIN = re.compile(LOGGED + r"(?P<line>\[\+\] VALID LOGIN:\t (?P<name>[^@\s]+@[^:\s]+):(?P<secret>.*))$")
REFUSED = re.compile(LOGGED + r"(?P<line>\[\+\] VALID LOGIN WITH ERROR:\t (?P<name>[^@\s]+@[^:\s]+):(?P<secret>.*)"
                     r"\t \((?P<why>[^\t]*)\))$")
VERSION = re.compile(r"^Version: \S+ \(\S*\) - .* - Ronnie Flathers @ropnop$")
ART = {"__             __               __", "/ /_____  _____/ /_  _______  __/ /____",
       "/ //_/ _ \\/ ___/ __ \\/ ___/ / / / __/ _ \\", "/ ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/",
       "/_/|_|\\___/_/  /_.___/_/   \\__,_/\\__/\\___/"}


def _body(line: creds.Line) -> creds.Line:
    """The line without the colour codes kerbrute writes around it, at its own byte offset."""
    start = LEAD.match(line.text).end()
    end = TRAIL.search(line.text, start).start()
    return creds.Line(line.text[start:end], line.at(start))


def sniff(data: bytes, hint: str | None = None) -> bool:
    try:
        text = data[:WINDOW].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return any(KNOWN.match(body) or VERSION.match(body) for body in (_body(line).text for line in creds.lines(text)))


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    held: dict[str, dict[str, Any]] = {}
    for line in map(_body, creds.lines(text)):
        rec = _record(line, raw)
        if rec is not None:
            rid = records.make_id(rec)
            if rid in held:
                records.merge(held[rid], rec)
            held.setdefault(rid, rec)
        elif line.text.strip() and not (OWN.match(line.text) or VERSION.match(line.text)
                                        or line.text.strip() in ART or WRAPPER.match(line.text)):
            raw.unread.append(line.text)
    return list(held.values())


def _record(line: creds.Line, raw: Input) -> dict[str, Any] | None:
    """The principal, login or AS-REP hash on one line; None for any other line."""
    def ref(match: re.Match[str], group: str) -> dict[str, Any]:
        return cite(raw.blob, raw.data, line.at(match.start(group)), line.at(match.end(group)), TOOL, raw.source)

    named = USERNAME.match(line.text)
    login = LOGIN.match(line.text) or REFUSED.match(line.text)
    if named is None and login is None:
        typed = hashformats.match(line.text)
        if typed is not None and typed.end == len(line.text) and typed.principal:
            return creds.credential_from_typed(typed, line, raw)
        return None
    match = named or login
    if named is not None or not login["secret"]:
        rec = records.new("principal")
        records.set_field(rec, "principal", match["name"], ref(match, "name"))
        return rec
    rec = records.new("credential")
    records.set_field(rec, "principal", login["name"], ref(login, "name"))
    records.set_field(rec, "secret", login["secret"], ref(login, "secret"))
    records.set_field(rec, "state", "confirmed", ref(login, "line"))
    if "why" in login.groupdict():
        raw.notices.append(f"{login['name']}: kerbrute found the password, but the domain controller refused a ticket "
                           f"({login['why']}). It is stored as a confirmed login; an expired password has to be "
                           "changed before it can be used.")
    return rec
