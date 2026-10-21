"""NetExec console output to hosts, services, credentials, shares, principals and findings.

Banners, logins, hashes, SAM and NTDS dumps, share tables, refusals, password policy and LDAP
attributes. A guest fallback, a failed login, a masked or empty secret is never a credential."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from lootlib import records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError, creds, hashformats
from lootlib.prov import TOOL, cite

NAME = "netexec"

PREFIX = re.compile(
    r"^(?P<protocol>[A-Za-z][\w.-]*) +"
    r"(?P<host>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39}) +"
    r"(?P<port>\d{1,5}) +"
    r"(?P<hostname>\S+) +"
    r"(?:\x1b\[[0-9;]*m)*"
)
MARKER = re.compile(r"^\[(?P<marker>[-+*])\] +")
PROGRESS = re.compile(r"^Running nxc against \d+ targets?\b")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
LOGGED = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| [^|\s]+:\d+ - [A-Z]+ - ")
ENUMERATED = "Enumerated shares"
SHARE_HEADER = ("Share", "Permissions", "Remark")
POLICY = re.compile(r"^Dumping password info for domain: *(?P<domain>\S+) *$")
REFUSED = re.compile(r"^Error (?P<operation>[^:]+): *(?P<reason>\S.*?) *$")
BANNER = re.compile(r"^(?P<head>\S.*?) +\(name:(?P<name>[^)\s]+)\)")
DOMAIN = re.compile(r"\(domain:(?P<domain>[^)\s]+)\)")
ATTRIBUTE_KEYS = ("sAMAccountName", "memberOf", "pwdLastSet", "lastLogon")
# Only MSSQL states a version, and a dotted number is what (Datacenter) lacks.
VERSION_TAIL = re.compile(r"^(?P<os>.*?) +\((?P<version>[^()]*\d+\.\d[^()]*)\)$")
LOGIN = re.compile(r"^(?P<realm>[^\\\s]+)\\(?P<principal>[^\s:\\]+):(?P<secret>.*)$")
NULL_SESSION = re.compile(r"^(?P<realm>[^\\\s]*)\\: *$")
STATUS = re.compile(r"\s+(?:STATUS_|KDC_ERR_)\S+\s*$")
GUEST, PWNED = " (Guest)", " (Pwn3d!)"
FLAGS = (("signing:False", "SMB signing not required"), ("SMBv1:True", "SMBv1 enabled"),
         ("Null Auth:True", "SMB null auth allowed"), ("DC:True", "Domain controller"))
CONFIRMED, FAILED = "confirmed", "failed"
NT_HASH = re.compile(r"^[0-9a-fA-F]{32}$")
MASK = re.compile(r"([^\w\s])\1{7}$")
DUMPING = {"Dumping SAM hashes": "sam", "Dumping the NTDS,": "ntds"}


@dataclass(frozen=True)
class _Login:
    realm: str
    principal: str
    secret: str
    at: int
    marker: str
    marker_at: int
    guest: bool
    pwned: bool

    @property
    def confirmed(self) -> bool:
        return self.marker == "+" and not self.guest


@dataclass(frozen=True)
class _Banner:
    prefixed: "re.Match[str]"
    name: str
    name_at: int
    os: str
    os_at: int
    version: str | None
    version_at: int


@dataclass
class _Policy:
    host: dict[str, Any] | None
    domain: str
    title_at: int
    title_text: str
    message_at: int
    start: int = -1
    end: int = -1
    lines: list = field(default_factory=list)

    def take(self, line: creds.Line, message: str) -> None:
        if self.start < 0:
            self.start = line.start
        self.end = line.end
        self.lines.append(message.rstrip())

    def finding(self, raw: Input) -> dict[str, Any] | None:
        """The policy block as one finding with no severity and no status."""
        if self.host is None or not any(self.lines):
            return None
        rec = records.new("finding")
        records.set_field(rec, "title", f"Password policy: {self.domain}", _ref(raw, self.title_at, self.title_text))
        records.set_field(rec, "description", "\n".join(self.lines).strip(),
                          _ref(raw, self.start, raw.data[self.start:self.end].decode("utf-8")))
        records.set_field(rec, "host_id", _id(self.host), self.host["prov"]["ip"])
        return rec


@dataclass
class _Table:
    host: dict[str, Any] | None
    columns: tuple[int, int] | None = None


def sniff(data: bytes, hint: str | None = None) -> bool:
    try:
        text = data[:WINDOW].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return any(_login_in(line) is not None or _hash_in(line) is not None or _banner_in(line) is not None
               for line in (_unlogged(creds.Line(t, 0)).text for t in text.splitlines()))


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    held: dict[str, dict[str, Any]] = {}
    guests: list[str] = []
    failures = 0
    tables: dict[str, _Table] = {}
    policies: dict[str, _Policy] = {}
    worked = _logins_that_worked(raw.known)
    realm: tuple[str, dict[str, Any]] | None = None
    domains: dict[str, tuple[str, dict[str, Any]]] = {}
    dumping: dict[str, str] = {}
    masked = 0

    def keep(rec: dict[str, Any]) -> None:
        rid = _id(rec)
        if rid in held and rec["type"] == "credential":
            records.merge(held[rid], rec)
        held.setdefault(rid, rec)

    for line in map(_unlogged, creds.lines(text)):
        announced_dump = _announces_dump(line.text)
        if announced_dump is not None:
            dumping[announced_dump[0]] = announced_dump[1]
            continue
        dumped = _dump_in(line.text)
        if dumped is not None:
            for rec in _dumped(dumped, line, raw, dumping, domains):
                keep(rec)
            continue
        announced_policy = _announces_policy(line.text)
        if announced_policy is not None:
            host_ip, domain, at, prefix_at = announced_policy
            policies[host_ip] = _Policy(held.get(f"host:{host_ip}"), domain, line.start + at,
                                        line.text[at:], prefix_at)
            continue
        collecting = _policy_line(line.text, policies)
        if collecting is not None:
            collecting.take(line, line.text[collecting.message_at:])
            continue
        announced = _announces_shares(line.text)
        if announced is not None:
            tables[announced] = _Table(held.get(f"host:{announced}"))
            continue
        table = _table_for(line.text, tables)
        if table is not None:
            share = _share_row(table, line, raw)
            if share is not None:
                keep(share)
            continue
        banner = _banner_in(line.text)
        if banner is not None:
            host = _host(banner, line, raw)
            held[_id(host)] = host
            keep(_service(banner, line, raw))
            for found in _flags(line, raw):
                keep(found)
            named = DOMAIN.search(line.text)
            if named is not None:
                realm = (named.group("domain"), _ref(raw, line.start + named.start("domain"), named.group("domain")))
                domains[banner.prefixed.group("host")] = realm
            continue
        attributes = _attributes_in(line.text)
        if attributes is not None:
            for rec in _account(attributes, realm, line, raw):
                keep(rec)
            continue
        refusal = _refusal_in(line.text)
        if refusal is not None:
            found = _refused(refusal, line, held, raw)
            if found is not None:
                keep(found)
            continue
        logon = _cached_in(line, raw)
        if logon is not None:
            keep(logon)
            continue
        hashed = _hash_in(line.text)
        if hashed is not None:
            at, typed = hashed
            keep(creds.credential_from_typed(typed, creds.Line(line.text[at:], line.start + at), raw))
            continue
        null = _null_session_in(line.text)
        if null is not None:
            keep(_login_host(line, raw))
            keep(_null_session(null, line, raw))
            continue
        login = _login_in(line.text)
        if login is None:
            bare = ANSI.sub("", line.text)
            if line.text.strip() and not WRAPPER.match(line.text) and (not _tool_line(bare) or _row(bare)):
                raw.unread.append(line.text)
            continue
        if login.guest:
            guests.append(f"{login.realm}\\{login.principal}")
            continue
        if not login.confirmed:
            refused = _refused_login(login, line, held, raw, worked)
            if refused is None:
                failures += 1
            else:
                keep(refused)
            continue
        keep(_login_host(line, raw))
        if not login.secret:
            keep(_empty_password(login, line, raw))
            continue
        if MASK.search(login.secret):
            masked += 1
            continue
        keep(_credential(login, line, raw))
        worked.add(_login_key(login.realm, login.principal, login.secret))

    for policy in policies.values():
        found = policy.finding(raw)
        if found is not None:
            keep(found)
    if guests:
        names = sorted(set(guests))
        raw.notices.append(
            f"{len(guests)} login(s) succeeded as Guest rather than as the account named on them "
            f"({', '.join(names[:3])}{', …' if len(names) > 3 else ''}). A guest fallback proves nothing "
            "about that account, so no credential was made from it. The lines are in raw/ verbatim.")
    if masked:
        raw.notices.append(
            f"{masked} login(s) worked but NetExec masked the secret (audit_mode in nxc.conf), so no "
            "credential was made from them. The lines are in raw/ verbatim.")
    if failures:
        raw.notices.append(
            f"{failures} login(s) failed and produced no credential. A password that did not work "
            "is not that account's password, and recording it would overwrite one that is.")
    return list(held.values())


def _unlogged(line: creds.Line) -> creds.Line:
    """A ``--log`` file line as the screen showed it: the logger's time and caller prefix dropped."""
    logged = LOGGED.match(line.text)
    return creds.Line(line.text[logged.end():], line.start + logged.end()) if logged else line


def _id(rec: dict[str, Any]) -> str:
    return records.make_id(rec)


def _ref(raw: Input, start: int, text: str) -> dict[str, Any]:
    return cite(raw.blob, raw.data, start, start + len(text.encode("utf-8")), TOOL, raw.source)


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= 48 else text[:47] + "…"


def _message(text: str) -> tuple[int, int, str, str] | None:
    """Where the marker sits, where the message starts, the marker, and the message."""
    prefixed = PREFIX.match(text)
    if not prefixed:
        return None
    at = prefixed.end()
    marked = MARKER.match(text[at:])
    if marked is None:
        return at, at, "", text[at:]
    return at, at + marked.end(), marked.group("marker"), text[at + marked.end():]


def _login_in(text: str) -> _Login | None:
    """The login result on this line; a username holding whitespace is two lines run together."""
    marked = _message(text)
    if marked is None:
        return None
    marker_at, at, marker, rest = marked
    if marker not in ("+", "-"):
        return None
    login = LOGIN.match(rest)
    if not login:
        return None
    secret, guest, pwned = login.group("secret"), False, False
    for suffix, flag in ((GUEST, "guest"), (PWNED, "pwned")):
        if secret.rstrip().endswith(suffix):
            secret = secret.rstrip()[: -len(suffix)]
            guest, pwned = guest or flag == "guest", pwned or flag == "pwned"
    secret = STATUS.sub("", secret).strip()
    if not secret and marker == "-":
        return None
    return _Login(login.group("realm"), login.group("principal"), secret, at + login.start("secret"),
                  marker, marker_at, guest, pwned)


def _banner_in(text: str) -> _Banner | None:
    """A starred message whose OS string is followed by ``(name:X)``."""
    prefixed = PREFIX.match(text)
    if not prefixed:
        return None
    marked = MARKER.match(text[prefixed.end():])
    if marked is None or marked.group("marker") != "*":
        return None
    at = prefixed.end() + marked.end()
    banner = BANNER.match(text[at:])
    if banner is None:
        return None
    head, head_at = banner.group("head"), at + banner.start("head")
    tail = VERSION_TAIL.match(head)
    if tail is None:
        return _Banner(prefixed, banner.group("name"), at + banner.start("name"), head, head_at, None, 0)
    return _Banner(prefixed, banner.group("name"), at + banner.start("name"), tail.group("os"),
                   head_at + tail.start("os"), tail.group("version"), head_at + tail.start("version"))


def _host(banner: _Banner, line: creds.Line, raw: Input) -> dict[str, Any]:
    prefixed = banner.prefixed
    host = records.new("host")
    records.set_field(host, "ip", prefixed.group("host"),
                      _ref(raw, line.start + prefixed.start("host"), prefixed.group("host")))
    records.set_field(host, "hostnames", [banner.name], [_ref(raw, line.offset_of(banner.name, banner.name_at),
                                                              banner.name)])
    records.set_field(host, "os", banner.os, _ref(raw, line.offset_of(banner.os, banner.os_at), banner.os))
    return host


def _service(banner: _Banner, line: creds.Line, raw: Input) -> dict[str, Any]:
    """The port the banner came back on; its name and version only when the banner states a
    version, since a scan's service name for the port is the better one."""
    prefixed, version = banner.prefixed, banner.version
    proto = prefixed.group("protocol")
    proto_ref = _ref(raw, line.start + prefixed.start("protocol"), proto)
    svc = records.new("service")
    records.set_field(svc, "host_id", f"host:{prefixed.group('host')}",
                      _ref(raw, line.start + prefixed.start("host"), prefixed.group("host")))
    records.set_field(svc, "port", int(prefixed.group("port")),
                      _ref(raw, line.start + prefixed.start("port"), prefixed.group("port")))
    records.set_field(svc, "protocol", "tcp", proto_ref)
    if version:
        records.set_field(svc, "name", proto.lower(), proto_ref)
        records.set_field(svc, "version", version, _ref(raw, line.offset_of(version, banner.version_at), version))
    return svc


def _flags(line: creds.Line, raw: Input) -> list[dict[str, Any]]:
    """Banner flags an operator acts on, each a finding on the host that printed it."""
    prefixed = PREFIX.match(line.text)
    out = []
    for flag, title in FLAGS:
        at = line.text.find(f"({flag})")
        if at < 0:
            continue
        stated = _ref(raw, line.start + at, f"({flag})")
        rec = records.new("finding")
        records.set_field(rec, "title", title, stated)
        records.set_field(rec, "host_id", f"host:{prefixed.group('host')}",
                          _ref(raw, line.start + prefixed.start("host"), prefixed.group("host")))
        records.set_field(rec, "status", CONFIRMED, stated)
        out.append(rec)
    return out


def _announces_policy(text: str):
    """The host and domain whose password policy follows, and the column its messages start at."""
    prefixed = PREFIX.match(text)
    if not prefixed:
        return None
    marked = MARKER.match(text[prefixed.end():])
    if marked is None or marked.group("marker") != "+":
        return None
    at = prefixed.end() + marked.end()
    found = POLICY.match(text[at:])
    if found is None:
        return None
    return prefixed.group("host"), found.group("domain"), at, prefixed.end()


def _policy_line(text: str, policies: dict[str, _Policy]) -> _Policy | None:
    prefixed = PREFIX.match(text)
    if not prefixed:
        return None
    policy = policies.get(prefixed.group("host"))
    if policy is None or MARKER.match(text[prefixed.end():]):
        return None
    return policy


def _announces_shares(text: str) -> str | None:
    """The host whose share table follows; a three-column table is read only once announced."""
    prefixed = PREFIX.match(text)
    if not prefixed:
        return None
    marked = MARKER.match(text[prefixed.end():])
    if marked is None or marked.group("marker") != "*":
        return None
    if text[prefixed.end() + marked.end():].strip() != ENUMERATED:
        return None
    return prefixed.group("host")


def _table_for(text: str, tables: dict[str, _Table]) -> tuple[_Table, int] | None:
    prefixed = PREFIX.match(text)
    if not prefixed:
        return None
    table = tables.get(prefixed.group("host"))
    if table is None or table.host is None:
        return None
    at = prefixed.end()
    if MARKER.match(text[at:]):
        return None
    return table, at


def _share_row(found: tuple[_Table, int], line: creds.Line, raw: Input) -> dict[str, Any] | None:
    """One row, sliced by the columns its header declared; a name overrunning its column is refused."""
    table, at = found
    message = line.text[at:]
    if table.columns is None:
        table.columns = _header_columns(message)
        return None
    if _overruns(message, table.columns):
        raw.notices.append(
            f"a share row does not fit the columns its table declared and was not read ({_clip(message)}). "
            "A share name longer than its column leaves no separator. The line is in raw/ verbatim.")
        return None
    name, permissions, remark = _cells(message, table.columns)
    if not name or set(name) == {"-"}:
        return None
    prefixed = PREFIX.match(line.text)
    share = records.new("share")
    records.set_field(share, "host_id", _id(table.host),
                      _ref(raw, line.start + prefixed.start("host"), prefixed.group("host")))
    records.set_field(share, "name", name, _ref(raw, line.offset_of(name, at), name))
    if permissions:
        records.set_field(share, "permissions", permissions, _ref(raw, line.offset_of(permissions, at), permissions))
    if remark:
        records.set_field(share, "remark", remark, _ref(raw, line.offset_of(remark, at), remark))
    return share


def _overruns(message: str, columns: tuple[int, int] | None) -> bool:
    if columns is None:
        return False
    return len(message) > columns[0] and message[columns[0] - 1] != " "


def _header_columns(message: str) -> tuple[int, int] | None:
    offsets = [message.find(label) for label in SHARE_HEADER]
    if any(at < 0 for at in offsets) or offsets != sorted(offsets):
        return None
    return offsets[1], offsets[2]


def _cells(message: str, columns: tuple[int, int] | None) -> tuple[str, str, str]:
    if columns is None:
        return "", "", ""
    permissions_at, remark_at = columns
    return (message[:permissions_at].strip(), message[permissions_at:remark_at].strip(),
            message[remark_at:].strip())


def _refusal_in(text: str):
    marked = _message(text)
    if marked is None:
        return None
    _, at, marker, rest = marked
    if marker != "-":
        return None
    found = REFUSED.match(rest)
    return None if found is None else (at, found)


def _refused(refusal, line: creds.Line, held: dict[str, dict[str, Any]], raw: Input) -> dict[str, Any] | None:
    """``[-] Error <operation>: <reason>`` as a failed finding, for a host a banner named."""
    at, found = refusal
    prefixed = PREFIX.match(line.text)
    host = held.get(f"host:{prefixed.group('host')}")
    if host is None or host["type"] != "host":
        raw.notices.append(f"a failure was reported for a host no line in this file names "
                           f"({_clip(line.text[at:])}). The line is in raw/ verbatim.")
        return None
    title = f"Error {found.group('operation')}"
    rec = records.new("finding")
    records.set_field(rec, "title", title, _ref(raw, line.start + at + found.start(), title))
    records.set_field(rec, "description", found.group("reason"),
                      _ref(raw, line.start + at + found.start("reason"), found.group("reason")))
    records.set_field(rec, "host_id", _id(host), host["prov"]["ip"])
    records.set_field(rec, "status", FAILED, _ref(raw, line.start + prefixed.end(),
                                                  line.text[prefixed.end():at + found.end("operation") + 1]))
    return rec


def _tool_line(text: str) -> bool:
    """A line NetExec printed: its padded column prefix or its progress bar."""
    return bool(PREFIX.match(text) and re.match(r"\S+ {2,}", text)) or bool(PROGRESS.match(text))


def _login_key(realm: str, principal: str, secret: str) -> tuple[str, str, str]:
    return realm.casefold(), principal.casefold(), secret.lower() if records.is_hex(secret) else secret


def _logins_that_worked(known: dict[str, dict[str, Any]]) -> set[tuple[str, str, str]]:
    return {_login_key(r["realm"], r["principal"], r[said]) for r in known.values()
            if r["type"] == "credential" and r.get("hosts") and r.get("realm") and r.get("principal")
            for said in ("secret", "secret_hash") if r.get(said)}


def _refused_login(login: _Login, line: creds.Line, held: dict[str, dict[str, Any]], raw: Input,
                   worked: set[tuple[str, str, str]]) -> dict[str, Any] | None:
    """A login refused here for a credential that authenticated elsewhere; else ``None``."""
    if _login_key(login.realm, login.principal, login.secret) not in worked:
        return None
    prefixed = PREFIX.match(line.text)
    host = held.get(f"host:{prefixed.group('host')}")
    if host is None or host["type"] != "host":
        raw.notices.append(f"a login that worked elsewhere was refused on a host no line in this file names "
                           f"({_clip(line.text)}). It was counted as a failure instead. The line is in raw/ verbatim.")
        return None
    named = login.at - 1
    rec = records.new("finding")
    records.set_field(rec, "title", f"{prefixed.group('protocol')} refused {login.realm}\\{login.principal}",
                      _ref(raw, line.start, line.text[:named]))
    records.set_field(rec, "host_id", _id(host), host["prov"]["ip"])
    records.set_field(rec, "status", FAILED, _ref(raw, line.start + login.marker_at, line.text[login.marker_at:named]))
    return rec


def _login_host(line: creds.Line, raw: Input) -> dict[str, Any]:
    """The host a login line answered from: its IP, and the name NetExec printed beside it."""
    prefixed = PREFIX.match(line.text)
    ip, name = prefixed.group("host"), prefixed.group("hostname")
    host = records.new("host")
    records.set_field(host, "ip", ip, _ref(raw, line.start + prefixed.start("host"), ip))
    if name != ip:
        records.set_field(host, "hostnames", [name], [_ref(raw, line.start + prefixed.start("hostname"), name)])
    return host


def _null_session_in(text: str) -> tuple[int, int] | None:
    """Where the marker and an empty-user ``[+] DOMAIN\\:`` login sit on this line."""
    marked = _message(text)
    if marked is None or marked[2] != "+" or not NULL_SESSION.match(marked[3]):
        return None
    return marked[0], marked[1] + len(marked[3].rstrip())


def _null_session(null: tuple[int, int], line: creds.Line, raw: Input) -> dict[str, Any]:
    """A login with no user and no password that the host accepted."""
    prefixed = PREFIX.match(line.text)
    marker_at, end = null
    accepted = _ref(raw, line.start + marker_at, line.text[marker_at:end])
    rec = records.new("finding")
    records.set_field(rec, "title", f"{prefixed.group('protocol')} null session accepted", accepted)
    records.set_field(rec, "host_id", f"host:{prefixed.group('host')}",
                      _ref(raw, line.start + prefixed.start("host"), prefixed.group("host")))
    records.set_field(rec, "status", CONFIRMED, accepted)
    return rec


def _empty_password(login: _Login, line: creds.Line, raw: Input) -> dict[str, Any]:
    """A named account the host let in with no password, as a finding naming that account."""
    prefixed = PREFIX.match(line.text)
    accepted = _ref(raw, line.start + login.marker_at, line.text[login.marker_at:login.at])
    rec = records.new("finding")
    records.set_field(rec, "title", f"{prefixed.group('protocol')} login with an empty password accepted "
                      f"({login.realm}\\{login.principal})", accepted)
    records.set_field(rec, "host_id", f"host:{prefixed.group('host')}",
                      _ref(raw, line.start + prefixed.start("host"), prefixed.group("host")))
    records.set_field(rec, "status", CONFIRMED, accepted)
    return rec


def _attributes_in(text: str) -> dict[str, tuple[str, int]] | None:
    """Account attributes located by key name, since every separator also occurs inside a DN."""
    marked = _message(text)
    if marked is None:
        return None
    _, at, marker, rest = marked
    if marker != "*":
        return None
    found = sorted((rest.find(f"{key}: "), key) for key in ATTRIBUTE_KEYS if rest.find(f"{key}: ") >= 0)
    if not any(key == "sAMAccountName" for _, key in found):
        return None
    attributes = {}
    for index, (start, key) in enumerate(found):
        value_at = start + len(key) + 2
        end = found[index + 1][0] if index + 1 < len(found) else len(rest)
        attributes[key] = (rest[value_at:end].rstrip().rstrip(","), at + value_at)
    return attributes


def _account(attributes, realm, line: creds.Line, raw: Input) -> list[dict[str, Any]]:
    """An attribute line as a principal, its groups, and a member_of edge to each."""
    principal = _principal(attributes, realm, line, raw)
    out = [principal]
    if "memberOf" not in attributes:
        return out
    member_of, member_at = attributes["memberOf"]
    names, truncated = _dns_in(member_of)
    if truncated:
        raw.notices.append(f"the groups {principal['principal']} is in were cut off mid-line ({_clip(member_of)}). "
                           "The names before the cut were read. The line is in raw/ verbatim.")
    for dn, offset in names:
        group = _group(dn, member_at + offset, line, raw)
        if group is None:
            raw.notices.append(f"{principal['principal']} is in something that is not a distinguished name "
                               f"({_clip(dn)}), so no group was made from it. The line is in raw/ verbatim.")
            continue
        edge = records.new("relationship")
        records.set_field(edge, "src_id", _id(principal), principal["prov"]["principal"])
        records.set_field(edge, "kind", "member_of",
                          _ref(raw, line.start + member_at - len("memberOf") - 2, "memberOf"))
        records.set_field(edge, "dst_id", _id(group), _ref(raw, line.start + member_at + offset, dn))
        out.extend([group, edge])
    return out


def _dns_in(member_of: str) -> tuple[list[tuple[str, int]], bool]:
    """Each DN in a ``memberOf`` value (list literal, bare name or ``[]``), and whether one was cut off."""
    text = member_of.strip()
    if not text:
        return [], False
    if not text.startswith("["):
        return [(text, member_of.index(text))], False
    base = member_of.index(text)
    for quote in ("'", '"'):
        names, at, dangling = [], 0, False
        while True:
            start = text.find(quote, at)
            if start < 0:
                break
            end = text.find(quote, start + 1)
            if end < 0:
                dangling = True
                break
            names.append((text[start + 1:end], base + start + 1))
            at = end + 1
        if names or dangling:
            return names, dangling
    return [], False


def _principal(attributes, realm, line: creds.Line, raw: Input) -> dict[str, Any]:
    sam, sam_at = attributes["sAMAccountName"]
    rec = records.new("principal")
    records.set_field(rec, "principal", sam, _ref(raw, line.start + sam_at, sam))
    if realm is not None:
        records.set_field(rec, "realm", *realm)
    for key, name in (("pwdLastSet", "pwd_last_set"), ("lastLogon", "last_logon")):
        if key in attributes and attributes[key][0]:
            rec["ext"][name] = attributes[key][0]
    return rec


def _group(dn: str, at: int, line: creds.Line, raw: Input) -> dict[str, Any] | None:
    return creds.group_from_dn(dn, line.start + at, raw)


def _hash_in(text: str):
    """A self-naming hash on an unmarked line; a ``[*]`` sentence that mentions one is not it."""
    marked = _message(text)
    if marked is None:
        return None
    _, at, marker, rest = marked
    if marker:
        return None
    typed = hashformats.match(rest)
    if typed is None or not typed.principal or rest[typed.end:].strip():
        return None
    return at, typed


def _row(text: str) -> bool:
    """An unmarked message after the column prefix: a table row or dumped secret, data Trove has no reader for."""
    marked = _message(text)
    return marked is not None and not marked[2] and bool(marked[3].strip())


def _cached_in(line: creds.Line, raw: Input) -> dict[str, Any] | None:
    """An unmarked cached logon, ``FQDN/user:$DCC2$…``, taken from the line's host."""
    marked = _message(line.text)
    if marked is None or marked[2]:
        return None
    rec = creds.cached_logon(creds.Line(line.text[marked[1]:], line.start + marked[1]), raw)
    if rec is not None:
        prefixed = PREFIX.match(line.text)
        ip = prefixed.group("host")
        records.set_field(rec, "host_id", [f"host:{ip}"], [_ref(raw, line.start + prefixed.start("host"), ip)])
    return rec


def _announces_dump(text: str) -> tuple[str, str] | None:
    """The host whose SAM or NTDS dump follows, and which of the two it is."""
    marked = _message(text)
    if marked is None or marked[2] not in ("*", "+"):
        return None
    for opening, kind in DUMPING.items():
        if marked[3].startswith(opening):
            return PREFIX.match(text).group("host"), kind
    return None


def _dump_in(text: str):
    """An unmarked ``user:rid:lm:nt:::`` line and where it starts."""
    marked = _message(text)
    if marked is None or marked[2]:
        return None
    dumped = creds.DUMP_LINE.match(marked[3])
    return None if dumped is None else (marked[1], dumped)


def _dumped(dumped, line: creds.Line, raw: Input, dumping: dict[str, str],
            domains: dict[str, tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """A dumped hash taken from the line's host. With no ``DOMAIN\\`` on it, a SAM account's realm
    is the host's name and an NTDS account's is the domain the host's banner named, as NetExec does."""
    at, found = dumped
    prefixed = PREFIX.match(line.text)
    ip, name = prefixed.group("host"), prefixed.group("hostname")
    kind = dumping.get(ip)
    taken = [_ref(raw, line.start + prefixed.start("host"), ip)]
    out = creds.from_dump(found, creds.Line(line.text[at:], line.start + at), raw)
    for rec in out:
        records.set_field(rec, "host_id", [f"host:{ip}"], taken)
        if rec.get("realm"):
            continue
        if kind == "sam":
            records.set_field(rec, "realm", name, _ref(raw, line.start + prefixed.start("hostname"), name))
        elif kind == "ntds" and ip in domains:
            records.set_field(rec, "realm", *domains[ip])
    return out


def _credential(login: _Login, line: creds.Line, raw: Input) -> dict[str, Any]:
    """A login that authenticated as the account on its own line; the marker cites ``state``,
    the line's IP cites ``hosts``, and the IP through ``(Pwn3d!)`` cites ``admin_hosts``.
    A pass-the-hash login printed the NT hash, so that is ``secret_hash``, not ``secret``."""
    prefixed = PREFIX.match(line.text)
    rec = records.new("credential")
    records.set_field(rec, "principal", login.principal, _ref(raw, line.offset_of(login.principal), login.principal))
    records.set_field(rec, "realm", login.realm, _ref(raw, line.offset_of(login.realm), login.realm))
    said = _ref(raw, line.offset_of(login.secret, login.at), login.secret)
    if NT_HASH.match(login.secret):
        records.set_field(rec, "secret_hash", login.secret, said)
        records.set_field(rec, "hash_type", "ntlm", said)
    else:
        records.set_field(rec, "secret", login.secret, said)
    records.set_field(rec, "state", CONFIRMED, _ref(raw, line.start + login.marker_at,
                                                     line.text[login.marker_at:login.at + len(login.secret)]))
    start, end = prefixed.start("host"), login.at + len(login.secret)
    records.set_field(rec, "hosts", [f"host:{prefixed.group('host')}"],
                      [_ref(raw, line.start + start, line.text[start:end])])
    if login.pwned:
        end = line.text.rindex(PWNED.strip()) + len(PWNED.strip())
        records.set_field(rec, "admin_hosts", [f"host:{prefixed.group('host')}"],
                          [_ref(raw, line.start + start, line.text[start:end])])
    return rec
