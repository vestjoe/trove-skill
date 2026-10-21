"""A NetExec workspace database (smb.db, winrm.db, mssql.db) to hosts, credentials and shares.

Reads the text copy ``sqlitedb`` renders: one ``<table> <id>`` line per row. A login or admin
relation is where a credential worked; a SAM hash is the host's whose name is its domain."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from lootlib import records
from lootlib.encoding import NotText, text_of
from lootlib.parsers import Input, ParserError, creds
from lootlib.prov import TOOL, cite

NAME = "netexec-db"

REQUIRED = {
    "hosts": ("id", "ip", "hostname", "domain", "os"),
    "users": ("id", "domain", "username", "password", "credtype"),
    "loggedin_relations": ("id", "userid", "hostid"),
    "admin_relations": ("id", "userid", "hostid"),
}
OPTIONAL = {"hosts": ("signing", "smbv1")}
SHARES = ("id", "hostid", "name", "remark", "read", "write")
COUNTED = ("groups", "dpapi_secrets", "conf_checks_results")
FLAGS = (("signing", "0", "SMB signing not required"), ("smbv1", "1", "SMBv1 enabled"))
PLAINTEXT = ("plaintext", "password")
NT_HASH = re.compile(r"^[0-9a-fA-F]{32}$")
LM_NT = re.compile(r"^(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32})$")
ROW = re.compile(r"^(?P<table>[a-z_]+) (?P<id>\d+)$")


@dataclass
class Row:
    line: creds.Line
    id: str
    values: dict[str, tuple[str, int]]

    def __getitem__(self, column: str) -> str:
        return self.values.get(column, ("", 0))[0]

    def ref(self, raw: Input, column: str, through: str | None = None) -> dict[str, Any]:
        """The value of ``column``, or from its name through the value of ``through``."""
        value, at = self.values[column]
        end_value, end_at = self.values[through or column]
        start = at - len(column) - 1 if through else at
        return self.span(raw, start, end_at + len(end_value))

    def whole(self, raw: Input) -> dict[str, Any]:
        return self.span(raw, 0, len(self.line.text))

    def span(self, raw: Input, start: int, end: int) -> dict[str, Any]:
        text = self.line.text
        begin = self.line.start + len(text[:start].encode("utf-8"))
        return cite(raw.blob, raw.data, begin, begin + len(text[start:end].encode("utf-8")), TOOL, raw.source)


def claims(tables: dict[str, list[str]]) -> bool:
    return all(set(columns) <= set(tables.get(table, ())) for table, columns in REQUIRED.items())


def wanted(tables: dict[str, list[str]]) -> dict[str, tuple[str, ...]]:
    """The columns rendered per table: the required ones, the optional ones present, and shares when whole."""
    out = {t: c + tuple(o for o in OPTIONAL.get(t, ()) if o in tables[t]) for t, c in REQUIRED.items()}
    if set(SHARES) <= set(tables.get("shares", ())):
        out["shares"] = SHARES
    return out


def sniff(data: bytes, hint: str | None = None) -> bool:
    return False


def parse(raw: Input) -> list[dict[str, Any]]:
    try:
        text = text_of(raw.data)
    except NotText as err:
        raise ParserError(str(err)) from err
    rows: dict[str, list[Row]] = {}
    for line in creds.lines(text):
        row = row_of(line)
        if row is None:
            raise ParserError(f"not a rendered NetExec database row: {line.text[:48]!r}")
        rows.setdefault(row[0], []).append(row[1])
    hosts = {row.id: row for row in rows.get("hosts", [])}
    out = [rec for row in hosts.values() for rec in _host(row, raw)]
    held: dict[str, dict[str, Any]] = {}
    unread = 0
    for row in rows.get("users", []):
        found = _credentials(row, hosts, rows, raw)
        unread += not found
        for rec in found:
            rid = records.make_id(rec)
            if rid in held:
                records.merge(held[rid], rec)
            held.setdefault(rid, rec)
    shares = [_share(row, hosts, raw) for row in rows.get("shares", [])]
    out += list(held.values()) + [s for s in shares if s is not None]
    if hosts:
        raw.notices.append(_ranges(hosts))
    if unread:
        raw.notices.append(f"{unread} account row(s) hold no password Trove reads (an empty one, an SSH key or a "
                           "hash that is not NT or LM:NT); they are kept in the stored database")
    if None in shares:
        raw.notices.append(f"{shares.count(None)} share row(s) name a host the database does not hold and "
                           "were not read")
    return out


def row_of(line: creds.Line) -> tuple[str, Row] | None:
    head, *cells = line.text.split("\t")
    found = ROW.match(head)
    if found is None:
        return None
    values, at = {}, len(head) + 1
    for cell in cells:
        column, eq, value = cell.partition("=")
        if not eq:
            return None
        values[column] = (value, at + len(column) + 1)
        at += len(cell) + 1
    return found.group("table"), Row(line, found.group("id"), values)


def _host(row: Row, raw: Input) -> list[dict[str, Any]]:
    """The host, and a finding for signing not required or SMBv1 on, cited to the column."""
    host = records.new("host")
    records.set_field(host, "ip", row["ip"], row.ref(raw, "ip"))
    if row["hostname"]:
        records.set_field(host, "hostnames", [row["hostname"]], [row.ref(raw, "hostname")])
    if row["os"]:
        records.set_field(host, "os", row["os"], row.ref(raw, "os"))
    out = [host]
    for column, value, title in FLAGS:
        if column in row.values and row[column] == value:
            stated = row.ref(raw, column, column)
            rec = records.new("finding")
            records.set_field(rec, "title", title, stated)
            records.set_field(rec, "host_id", f"host:{row['ip']}", row.ref(raw, "ip"))
            records.set_field(rec, "status", "confirmed", stated)
            out.append(rec)
    return out


def _credentials(row: Row, hosts: dict[str, Row], rows: dict[str, list[Row]], raw: Input) -> list[dict[str, Any]]:
    """The account's password or hashes; logins set ``hosts``, admin logins ``admin_hosts`` too.
    An LM:NT hash whose domain is one held host's name was dumped from that host's SAM."""
    secret, kind = row["password"], row["credtype"].lower()
    pair = LM_NT.match(secret)
    if not secret or kind not in PLAINTEXT + ("hash",) or (kind == "hash" and not (pair or NT_HASH.match(secret))):
        return []
    rec = _account(row, raw)
    if kind in PLAINTEXT:
        records.set_field(rec, "secret", secret, row.ref(raw, "password"))
    else:
        nt_at = row.values["password"][1] + (33 if pair else 0)
        nt = pair.group("nt") if pair else secret
        records.set_field(rec, "secret_hash", nt, row.span(raw, nt_at, nt_at + 32))
        records.set_field(rec, "hash_type", "ntlm", row.ref(raw, "credtype"))
    out = [rec]
    if pair and pair.group("lm").lower() != creds.EMPTY_LM:
        lm = _account(row, raw)
        at = row.values["password"][1]
        records.set_field(lm, "secret_hash", pair.group("lm"), row.span(raw, at, at + 32))
        records.set_field(lm, "hash_type", "lm", row.ref(raw, "credtype"))
        out.append(lm)
    dumped_from = [h for h in hosts.values()
                   if pair and h["hostname"] and h["hostname"].casefold() == row["domain"].casefold()]
    for each in out:
        if len(dumped_from) == 1:
            records.set_field(each, "host_id", [f"host:{dumped_from[0]['ip']}"], [row.ref(raw, "domain")])
        records.set_field(each, "state", "found", row.ref(raw, "password"))
    admin = _relations(row, hosts, rows, raw, "admin_relations")
    worked = _relations(row, hosts, rows, raw, "loggedin_relations")
    worked += [(h, r) for h, r in admin if h not in {w for w, _ in worked}]
    if worked:
        records.set_field(rec, "state", "confirmed", worked[0][1])
        records.set_field(rec, "hosts", [h for h, _ in worked], [r for _, r in worked])
    if admin:
        records.set_field(rec, "admin_hosts", [h for h, _ in admin], [r for _, r in admin])
    return out


def _account(row: Row, raw: Input) -> dict[str, Any]:
    rec = records.new("credential")
    records.set_field(rec, "principal", row["username"], row.ref(raw, "username"))
    if row["domain"]:
        records.set_field(rec, "realm", row["domain"], row.ref(raw, "domain"))
    return rec


def _relations(row: Row, hosts: dict[str, Row], rows: dict[str, list[Row]], raw: Input,
               table: str) -> list[tuple[str, dict[str, Any]]]:
    """Each held host this account has a ``table`` row for, cited to that row."""
    seen, out = set(), []
    for rel in rows.get(table, []):
        host = hosts.get(rel["hostid"])
        if rel["userid"] == row.id and host is not None and host["ip"] not in seen:
            seen.add(host["ip"])
            out.append((f"host:{host['ip']}", rel.whole(raw)))
    return out


def _share(row: Row, hosts: dict[str, Row], raw: Input) -> dict[str, Any] | None:
    """A share on the host its ``hostid`` names: a host id, or the host name NetExec writes there."""
    named = [h for h in hosts.values() if h.id == row["hostid"]] or [
        h for h in hosts.values() if h["hostname"] and h["hostname"].casefold() == row["hostid"].casefold()]
    if len(named) != 1 or not row["name"]:
        return None
    share = records.new("share")
    records.set_field(share, "host_id", f"host:{named[0]['ip']}", row.ref(raw, "hostid"))
    records.set_field(share, "name", row["name"], row.ref(raw, "name"))
    permissions = ",".join(p for p, column in (("READ", "read"), ("WRITE", "write")) if row[column] == "1")
    if permissions:
        records.set_field(share, "permissions", permissions, row.ref(raw, "read", "write"))
    if row["remark"]:
        records.set_field(share, "remark", row["remark"], row.ref(raw, "remark"))
    return share


def _ranges(hosts: dict[str, Row]) -> str:
    """How many hosts the database holds, by /24, since NetExec keeps every run in one workspace."""
    counts: dict[str, int] = {}
    for row in hosts.values():
        try:
            v4 = ipaddress.ip_address(row["ip"]).version == 4
        except ValueError:
            v4 = False
        key = str(ipaddress.ip_network(f"{row['ip']}/24", strict=False)) if v4 else row["ip"]
        counts[key] = counts.get(key, 0) + 1
    ranges = ", ".join(f"{key} ({n})" for key, n in sorted(counts.items()))
    return (f"the database holds {len(hosts)} host(s): {ranges}. NetExec keeps every run in its workspace, so "
            "hosts from another engagement may be among them; a workspace per engagement keeps them apart")
