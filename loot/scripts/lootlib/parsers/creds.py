"""Credential dumps and cracks to credential records.

Shapes: secretsdump ``user:rid:lm:nt:::``, ``user:CLEARTEXT:pass`` and LSA service and autologon
passwords, a self-named hash stating its account, and hashcat ``hash:plaintext``, which joins its
owner by exact hash equality or is reported."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from lootlib import find, records
from lootlib.encoding import WINDOW, NotText, text_of
from lootlib.parsers import WRAPPER, Input, ParserError, hashformats
from lootlib.prov import TOOL, cite

NAME = "creds"

DUMP_LINE = re.compile(r"^(?P<principal>(?:(?! {2})[^:\r\n])+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):")
MACHINE_LINE = re.compile(r"^(?P<principal>[^:\s]+\$):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::\s*$")
CRACK_LINE = re.compile(r"^(?P<hash>[0-9a-fA-F]{16,}):(?P<plain>.+)$")
SECTION = re.compile(r"^\[\*\]\s+(?P<name>\S+)\s*$")
SERVICE_SECTION = re.compile(r"^_SC_(?P<service>.+)$")
CLEARTEXT = re.compile(r"^(?P<principal>[^:\s][^:]*):(?P<secret>.+)$")
NTDS_CLEARTEXT = re.compile(r"^(?P<principal>[^:\s][^:]*):CLEARTEXT:(?P<secret>(?!0x[0-9a-fA-F]+$).+)$")
AUTOLOGON = "DEFAULTPASSWORD"
UNKNOWN_USER = records.UNKNOWN_USER
IMPACKET = re.compile(r"^(?:Impacket v\S+ - Copyright |\[(?:SMB|SMBv2|HTTP|HTTPS|LDAP|MSSQL|FTP|SMTP|IMAP|POP3|DNS|LLMNR"
                      r"|NBT-NS|MDNS|WPAD|RDP|WinRM|Kerberos|SNMP)\] "
                      r"|\[-\] User \S+ doesn't have UF_DONT_REQUIRE_PREAUTH set$"
                      r"|\[-\] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN\([^()]*\)$"
                      r"|\[-\] Principal: \S+ - Kerberos SessionError: KDC_ERR_\w+\([^()]*\)$"
                      r"|\[-\] CCache file is not found\. Skipping\.\.\.$)")
HASHCAT = re.compile(r"^(?:hashcat \(\S+\) starting|[A-Z]\w*(?:\.[\w#]+)*\.{2,}: |(?:Started|Stopped): |\[s\]tatus \[)")
HEXDUMP = re.compile(r"^ [0-9a-f]{4}   (?:[0-9A-F]{2} ){1,8}")
HEXY = re.compile(r"[0-9a-fA-F]{16,}")
PLAIN_COLUMNS = re.compile(r"^(?P<plain>.*):(?P<hex>(?:[0-9a-fA-F]{2})+)(?::\d+)?$")
HEX_PLAIN = re.compile(r"^\$HEX\[(?P<hex>[0-9a-fA-F]*)\]$")
SAM_SECTION = "[*] Dumping local SAM hashes"
MACHINE_ACCOUNT = "$MACHINE.ACC"
DN_PART = re.compile(r"(?P<key>[A-Za-z]+)=(?P<value>[^,]*)")
SPN_HEADER = ("ServicePrincipalName", "Name", "MemberOf")
NPUSERS_HEADER = ("Name", "MemberOf", "PasswordLastSet", "LastLogon", "UAC")
CACHED = re.compile(r"^(?P<realm>[^/\s:\x00]+)\x00?/(?P<principal>[^/:\s]+):(?=\$DCC2\$)")
CACHED_TAIL = re.compile(r"^(?:: \([^()]*\))?\s*$")
CLIENT = re.compile(r"^\[\w+\] \S+ +Client +: +(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})\s*$")
LOGGED = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M - ")
SHOWN_HASH = re.compile(r"^\[\w+\] \S+ +Hash +: +(?P<hash>\S+)\s*$")
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
FOUND, CRACKED = "found", "cracked"


def decode_plain(plain: str) -> tuple[str, bool]:
    """A hashcat plaintext with ``$HEX[...]`` decoded, and whether it is readable.
    Odd-length or non-hex bodies are literal passwords; non-UTF-8 bytes stay encoded."""
    found = HEX_PLAIN.match(plain)
    if not found or len(found.group("hex")) % 2:
        return plain, True
    try:
        return bytes.fromhex(found.group("hex")).decode("utf-8"), True
    except (ValueError, UnicodeDecodeError):
        return plain, False


def plain_only(plain: str) -> str:
    """The password out of a hashcat ``--outfile-format`` line that adds the hex plain (and the
    crack position) after it; anything else is returned whole."""
    columns = PLAIN_COLUMNS.match(plain)
    if columns and bytes.fromhex(columns.group("hex")) == decode_plain(columns.group("plain"))[0].encode("utf-8"):
        return columns.group("plain")
    return plain


@dataclass(frozen=True)
class Line:
    text: str
    start: int

    @property
    def end(self) -> int:
        return self.start + len(self.text.encode("utf-8"))

    def offset_of(self, needle: str, from_: int = 0) -> int:
        """Byte offset in the blob of ``needle``, searching this line only."""
        at = self.text.find(needle, from_)
        return -1 if at < 0 else self.start + len(self.text[:at].encode("utf-8"))


def unlogged(line: Line) -> Line:
    """A Responder session-log line as the screen showed it: the logger's time prefix dropped."""
    logged = LOGGED.match(line.text)
    return Line(line.text[logged.end():], line.start + logged.end()) if logged else line


def lines(text: str) -> list[Line]:
    out, offset = [], 0
    for raw_line in text.splitlines(keepends=True):
        out.append(Line(raw_line.rstrip("\r\n"), offset))
        offset += len(raw_line.encode("utf-8"))
    return out


def sniff(data: bytes, hint: str | None = None) -> bool:
    """Any line of a shape this parser reads; a scheme-only hash (bcrypt) does not count."""
    try:
        text = data[:WINDOW].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    rows = [unlogged(Line(t, 0)).text for t in text.splitlines()]
    return any(_claimable(t) for t in rows) or any(
        _table_header(t) and nxt.startswith("---") for t, nxt in zip(rows, rows[1:]))


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    by_hash: dict[str, list[dict[str, Any]]] = {}
    for rec in raw.known.values():
        if rec["type"] == "credential" and rec.get("secret_hash"):
            by_hash.setdefault(rec["secret_hash"].lower(), []).append(rec)
    out: list[dict[str, Any]] = []
    unmatched: list[str] = []
    unowned: list[str] = []
    unread: list[str] = []
    undecoded: list[str] = []
    ownerless: list[dict[str, Any]] = []
    service: tuple[str, Line] | None = None
    section, local, machine, client = "", [], None, None
    dumps: list[dict[str, Any]] = []
    spn_table: tuple[Line, dict[str, int]] | None = None

    def keep(rec: dict[str, Any]) -> None:
        out.append(rec)
        if rec.get("secret_hash"):
            by_hash.setdefault(rec["secret_hash"].lower(), []).append(rec)

    for line in map(unlogged, lines(text)):
        if _table_header(line.text):
            columns = {m.group(): m.start() for m in re.finditer(r"\S+", line.text)}
            spn_table = (line, columns)
            continue
        if spn_table is not None:
            if not line.text.strip():
                spn_table = None
            elif not line.text.startswith("-"):
                out.extend(_spn_row(line, *spn_table, raw))
            continue
        banner = SECTION.match(line.text)
        if banner:
            named = SERVICE_SECTION.match(banner.group("name"))
            service = (named.group("service"), line) if named else None
            if banner.group("name").upper().startswith(AUTOLOGON):
                service = (banner.group("name"), line)
            section = banner.group("name")
            continue
        if line.text.startswith("[*]"):
            service, section = None, "sam" if line.text.startswith(SAM_SECTION) else ""
            continue
        heard = CLIENT.match(line.text)
        if heard:
            client = _client_host(heard, line, raw)
            out.append(client)
            continue
        dumped = DUMP_LINE.match(line.text) or MACHINE_LINE.match(line.text)
        if dumped:
            found = from_dump(dumped, line, raw)
            if section == "sam":
                local += found
            if section == MACHINE_ACCOUNT and dumped.group("principal").endswith("$"):
                machine = _machine_name(dumped, line)
                local += found
            for rec in found:
                keep(rec)
            dumps += found[:1]
            continue
        clear = NTDS_CLEARTEXT.match(line.text)
        if clear:
            keep(_from_cleartext(clear, line, raw))
            continue
        shown = SHOWN_HASH.match(line.text)
        if shown:
            line = Line(shown.group("hash"), line.offset_of(shown.group("hash"), shown.start("hash")))
        logon = cached_logon(line, raw)
        if logon is not None:
            keep(logon)
            continue
        typed = hashformats.match(line.text)
        rest = line.text[typed.end:] if typed else ""
        if typed and not rest:
            if typed.principal:
                rec = credential_from_typed(typed, line, raw)
                if client is not None and typed.type_name.startswith("netntlm"):
                    records.set_field(rec, "host_id", [client["id"]], [client["prov"]["ip"]])
                    client = None
                keep(rec)
            else:
                unowned.append(typed.text)
            continue
        if typed and rest.startswith(":"):
            plain, plain_at = plain_only(rest[1:]), typed.end + 1
            if not decode_plain(plain)[1]:
                undecoded.append(plain)
            owners = by_hash.get(typed.text.lower(), [])
            if owners:
                out.extend(_from_crack(typed.text, plain, 0, plain_at, line, raw, o) for o in owners)
            elif typed.principal:
                keep(credential_from_typed(typed, line, raw, plain=plain, plain_at=plain_at))
            else:
                unmatched.append(typed.text)
            continue
        cracked = CRACK_LINE.match(line.text)
        if cracked:
            hashed, plain = cracked.group("hash"), plain_only(cracked.group("plain"))
            if not decode_plain(plain)[1]:
                undecoded.append(plain)
            owners = by_hash.get(hashed.lower(), [])
            if not owners:
                unmatched.append(hashed)
                continue
            out.extend(_from_crack(hashed, plain, cracked.start("hash"), cracked.start("plain"), line, raw, o)
                       for o in owners)
            continue
        if service is not None:
            clear = CLEARTEXT.match(line.text)
            if clear and clear.group("principal") != UNKNOWN_USER and (
                    " " in clear.group("principal").strip() or clear.group("secret")[:1].isspace()):
                clear = None
            if clear and clear.group("principal") == UNKNOWN_USER:
                ownerless.append(_from_service_secret(clear, line, raw, *service))
                keep(ownerless[-1])
                continue
            if clear:
                keep(_from_service_secret(clear, line, raw, *service))
                continue
        if HEXY.search(line.text):
            unread.append(line.text)
        if line.text.strip() and not any(p.match(line.text) for p in (IMPACKET, HASHCAT, HEXDUMP, WRAPPER)):
            raw.unread.append(line.text)

    if local or ownerless:
        _local_to(machine, local, raw, ownerless)
    raw.apart = [r for r in dumps if r not in local and not r.get("realm") and not r.get("host_id")]
    raw.unresolved.extend(unmatched)
    _notice(raw, unmatched, "cracked hash(es) match no credential in this engagement yet",
            "They are applied by themselves when a file holding those hashes is imported.")
    _notice(raw, unowned, "hash(es) name a scheme and no account",
            "A credential is keyed on whose it is, so these are stored in raw/ and nothing was invented to own them.")
    _notice(raw, undecoded, "cracked password(s) are $HEX-encoded bytes that are not text",
            "The encoding is stored rather than a lossy decode of it.")
    if ownerless:
        raw.notices.append(f"{len(ownerless)} password(s) were dumped with no account; each is a credential "
                           f"with principal {UNKNOWN_USER}, tied to no account.")
    _notice(raw, unread, "line(s) carry something hash-shaped that no format here reads",
            "They are in raw/ verbatim.")
    return out


def _notice(raw: Input, items: list[str], what: str, then: str) -> None:
    if items:
        shown = ", ".join(_clip(i) for i in items[:3]) + (", …" if len(items) > 3 else "")
        raw.notices.append(f"{len(items)} {what} ({shown}). {then}")


def _ref(raw: Input, start: int, text: str) -> dict[str, Any]:
    return cite(raw.blob, raw.data, start, start + len(text.encode("utf-8")), TOOL, raw.source)


def group_from_dn(dn: str, start: int, raw: Input) -> dict[str, Any] | None:
    """A group read out of its DN at byte ``start``; name, realm and dn all cite the DN."""
    first = DN_PART.match(dn.strip())
    name = first.group("value").strip() if first else ""
    if not name:
        return None
    realm = ".".join(p.group("value") for p in DN_PART.finditer(dn) if p.group("key").upper() == "DC")
    whole = _ref(raw, start, dn)
    rec = records.new("group")
    records.set_field(rec, "name", name, whole)
    records.set_field(rec, "dn", dn, whole)
    if realm:
        records.set_field(rec, "realm", realm, whole)
    return rec


def _spn_row(line: Line, header: Line, cols: dict[str, int], raw: Input) -> list[dict[str, Any]]:
    """One GetUserSPNs or GetNPUsers row: the account in Name, and a member_of edge to the group in MemberOf."""
    name = line.text[cols["Name"]:cols["MemberOf"]].strip()
    dn = line.text[cols["MemberOf"]:cols.get("PasswordLastSet", len(line.text))].strip()
    if not name or not dn:
        return []
    group = group_from_dn(dn, line.offset_of(dn, cols["MemberOf"]), raw)
    if group is None:
        return []
    principal = records.new("principal")
    records.set_field(principal, "principal", name, _ref(raw, line.offset_of(name, cols["Name"]), name))
    if group.get("realm"):
        records.set_field(principal, "realm", group["realm"], group["prov"]["realm"])
    edge = records.new("relationship")
    records.set_field(edge, "src_id", records.make_id(principal), principal["prov"]["principal"])
    records.set_field(edge, "kind", "member_of", _ref(raw, header.offset_of("MemberOf"), "MemberOf"))
    records.set_field(edge, "dst_id", records.make_id(group), group["prov"]["dn"])
    return [principal, group, edge]


def _client_host(heard: re.Match[str], line: Line, raw: Input) -> dict[str, Any]:
    """The host a capture tool heard a hash from; the hashes below it were taken there."""
    host = records.new("host")
    records.set_field(host, "ip", heard.group("ip"), _ref(raw, line.offset_of(heard.group("ip")), heard.group("ip")))
    host["id"] = records.make_id(host)
    return host


def _machine_name(dumped: re.Match[str], line: Line) -> tuple[str, int]:
    """``DOMAIN\\NAME$`` under ``$MACHINE.ACC``: the dumped machine's own name and where it sits."""
    written = dumped.group("principal")
    name = written.rpartition("\\")[2].removesuffix("$")
    return name, line.offset_of(name, written.rfind(name))


def _local_to(machine: tuple[str, int] | None, local: list[dict[str, Any]], raw: Input,
              ownerless: list[dict[str, Any]]) -> None:
    """SAM accounts belong to the machine the dump names: its name is their realm, and the one
    held host of that name is where they, and passwords dumped with no account, were taken."""
    if machine is None:
        if local:
            raw.notices.append(f"{len(local)} local account(s) were dumped from a machine this file does not name "
                               "(no $MACHINE.ACC section), so they are tied to no host.")
        return
    name, at = machine
    named = find.host_ids_named(raw.known, name)
    for rec in local:
        if not rec.get("realm"):
            records.set_field(rec, "realm", name, _ref(raw, at, name))
    for rec in local + ownerless:
        if len(named) == 1:
            records.set_field(rec, "host_id", named, [_ref(raw, at, name)])
    if len(named) != 1:
        raw.unresolved.append(name)
        dumped = f"{len(local)} local account(s)" if local else f"{len(ownerless)} password(s) with no account"
        raw.notices.append(f"{dumped} belong to {name}, which "
                           f"{'no host Trove holds' if not named else 'several held hosts'} is called. "
                           "They are tied to it when a scan names it.")


def _account(rec: dict[str, Any], written: str, at: int, raw: Input) -> None:
    """``DOMAIN\\user`` as realm and principal, each citing its part; a bare name is the principal."""
    realm, _, principal = written.rpartition("\\")
    records.set_field(rec, "principal", principal, _ref(raw, at + len((realm + "\\").encode()) if realm else at,
                                                        principal))
    if realm:
        records.set_field(rec, "realm", realm, _ref(raw, at, realm))


def apart_notice(count: int) -> str:
    """The note for dump lines that joined no account a host is known for."""
    return (f"{count} dumped line(s) name no domain and no host, as in a dump file saved without its screen "
            "output, so no machine is known for them. The NetExec log or screen output of the same run names "
            "it: imported, it joins each line to that machine's account, except the empty password's hash "
            "and a hash several machines hold.")


def from_dump(match: re.Match[str], line: Line, raw: Input) -> list[dict[str, Any]]:
    """The NT hash, and the LM hash too when it is not the blank sentinel."""
    principal = match.group("principal")

    def dumped(secret_hash: str, hash_type: str, group: str) -> dict[str, Any]:
        rec = records.new("credential")
        at = line.offset_of(secret_hash, match.start(group))
        _account(rec, principal, line.offset_of(principal), raw)
        records.set_field(rec, "secret_hash", secret_hash, _ref(raw, at, secret_hash))
        records.set_field(rec, "hash_type", hash_type, _legend_ref(raw, "lmhash" if group == "lm" else "nthash",
                                                                   at, secret_hash))
        records.set_field(rec, "state", FOUND, _ref(raw, at, secret_hash))
        if "rid" in match.groupdict():
            rec["ext"]["rid"] = match.group("rid")
        return rec

    out = [dumped(match.group("nt"), "ntlm", "nt")]
    if match.group("lm").lower() != EMPTY_LM:
        out.append(dumped(match.group("lm"), "lm", "lm"))
    return out


def credential_from_typed(typed: hashformats.TypedHash, line: Line, raw: Input,
                          plain: str | None = None, plain_at: int = 0) -> dict[str, Any]:
    """A hash that names its own account; shared with netexec. ``plain`` is a crack on the
    same line. Each field cites the exact bytes it was read from."""
    def sub(name: str) -> dict[str, Any]:
        value = typed.groups[name]
        return _ref(raw, line.offset_of(value, typed.at[name]), value)

    rec = records.new("credential")
    records.set_field(rec, "principal", typed.principal, sub("principal"))
    if typed.realm:
        records.set_field(rec, "realm", typed.realm, sub("realm"))
    records.set_field(rec, "secret_hash", typed.text, _ref(raw, line.start, typed.text))
    records.set_field(rec, "hash_type", typed.type_name, _typed_hash_type_ref(raw, line, typed))
    state_ref = _ref(raw, line.start, typed.text)
    if plain is not None:
        secret, _ = decode_plain(plain)
        if secret:
            state_ref = _ref(raw, line.offset_of(plain, plain_at), plain)
            records.set_field(rec, "secret", secret, state_ref)
        else:
            state_ref = _ref(raw, line.start, line.text)
            rec["ext"]["secret_empty"] = True
    records.set_field(rec, "state", CRACKED if plain is not None else FOUND, state_ref)
    for extra in typed.fmt.extras:
        if extra in typed.groups:
            rec["ext"][extra] = typed.groups[extra]
    if typed.fmt.name == "kerberos-key":
        key = f"{typed.type_name}:{typed.groups['key']}"
        records.set_field(rec, "keys", [key], [_ref(raw, line.offset_of(key, typed.at["etype"]), key)])
    return rec


def cached_logon(line: Line, raw: Input) -> dict[str, Any] | None:
    """secretsdump's ``FQDN/user:$DCC2$...: (time)``: the cached hash, realm from the FQDN.
    Impacket may end the FQDN with a NUL; the realm leaves it out."""
    cached = CACHED.match(line.text)
    if cached is None:
        return None
    hashed = Line(line.text[cached.end():], line.offset_of(line.text[cached.end():], cached.end()))
    typed = hashformats.match(hashed.text)
    if typed is None or typed.fmt.name != "dcc2" or not CACHED_TAIL.match(hashed.text[typed.end:]):
        return None
    rec = credential_from_typed(typed, hashed, raw)
    realm = cached.group("realm")
    records.set_field(rec, "realm", realm, _ref(raw, line.start, realm))
    return rec


def _from_cleartext(match: re.Match[str], line: Line, raw: Input) -> dict[str, Any]:
    """An NTDS ``DOMAIN\\user:CLEARTEXT:password``: the account's stored reversible password."""
    principal, secret = match.group("principal"), match.group("secret")
    secret_ref = _ref(raw, line.offset_of(secret, match.start("secret")), secret)
    rec = records.new("credential")
    _account(rec, principal, line.offset_of(principal), raw)
    records.set_field(rec, "secret", secret, secret_ref)
    records.set_field(rec, "state", FOUND, secret_ref)
    return rec


def _from_service_secret(match: re.Match[str], line: Line, raw: Input, service: str, banner: Line) -> dict[str, Any]:
    """A cleartext ``DOMAIN\\user:password`` that exists because a ``[*] _SC_<name>`` or
    ``[*] DefaultPassword`` banner stood above it."""
    principal, secret = match.group("principal"), match.group("secret")
    secret_ref = _ref(raw, line.offset_of(secret, match.start("secret")), secret)
    rec = records.new("credential")
    _account(rec, principal, line.offset_of(principal), raw)
    records.set_field(rec, "secret", secret, secret_ref)
    records.set_field(rec, "source", service, _ref(raw, banner.offset_of(service), service))
    records.set_field(rec, "state", FOUND, secret_ref)
    return rec


def _from_crack(hashed: str, plain: str, hash_at: int, plain_at: int, line: Line, raw: Input,
                owner: dict[str, Any]) -> dict[str, Any]:
    """A crack joined to its owner: same id, so it fills ``secret`` on that credential.
    Principal, realm and hash type carry the owner's citations; the potfile never named them."""
    rec = records.new("credential")
    records.set_field(rec, "principal", owner["principal"], owner["prov"]["principal"])
    for carried in ("realm", "hash_type"):
        if owner.get(carried) and carried in owner["prov"]:
            records.set_field(rec, carried, owner[carried], owner["prov"][carried])
    records.set_field(rec, "secret_hash", hashed, _ref(raw, line.offset_of(hashed, hash_at), hashed))
    secret, _ = decode_plain(plain)
    state_ref = _ref(raw, line.start, line.text)
    if secret:
        state_ref = _ref(raw, line.offset_of(plain, plain_at), plain)
        records.set_field(rec, "secret", secret, state_ref)
    else:
        rec["ext"]["secret_empty"] = True
    records.set_field(rec, "state", CRACKED, state_ref)
    return rec


def _legend_ref(raw: Input, word: str, at: int, value: str) -> dict[str, Any]:
    """secretsdump's column legend names the hash type; without one, the hash is cited."""
    legend = raw.data.find(word.encode())
    return _ref(raw, legend, word) if legend >= 0 else _ref(raw, at, value)


def _typed_hash_type_ref(raw: Input, line: Line, typed: hashformats.TypedHash) -> dict[str, Any]:
    """The token the format names itself with; the NetNTLM pair name nothing, so the line."""
    named = typed.fmt.name_group
    if named and named in typed.groups:
        value = typed.groups[named]
        return _ref(raw, line.offset_of(value, typed.at[named]), value)
    tag = typed.fmt.tag
    if tag and tag in line.text:
        return _ref(raw, line.offset_of(tag), tag)
    return _ref(raw, line.start, line.text)


def _table_header(line: str) -> bool:
    return any(all(f" {word} " in f" {line} " for word in header) for header in (SPN_HEADER, NPUSERS_HEADER))


def _claimable(line: str) -> bool:
    if DUMP_LINE.match(line) or MACHINE_LINE.match(line) or CRACK_LINE.match(line):
        return True
    shown = SHOWN_HASH.match(line)
    if shown and hashformats.match(shown.group("hash")) is not None:
        return True
    cached = CACHED.match(line)
    if cached and hashformats.match(line[cached.end():]) is not None:
        return True
    typed = hashformats.match(line)
    return typed is not None and typed.fmt.claims


def _clip(text: str) -> str:
    return text[:24] + "…" if len(text) > 24 else text
