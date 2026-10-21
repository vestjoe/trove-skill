"""Search over every record: types, field conditions, free text, origin."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from lootlib import records
from lootlib.errors import LootError
from lootlib.prov import ORIGINS_HELP

ALIASES = {"host": "host_id", "service": "service_id", "ip_address": "ip"}
OPS = ("!=", "=", ">", "<", "~")
_COND = re.compile(r"^(?P<field>[A-Za-z_]+)\s*(?P<op>!=|=|>|<|~)\s*(?P<value>.*)$")
_UNARY = re.compile(r"^(?P<field>[A-Za-z_]+)(?P<op>[?!])$")
DEFAULT_LIMIT = 50
HOST_LINKS = {"host_id", "hosts", "admin_hosts"}
PROTOCOLS = {
    "smb": ({"microsoft-ds", "netbios-ssn", "smb"}, {139, 445}),
    "rdp": ({"ms-wbt-server", "rdp"}, {3389}),
    "winrm": ({"wsman", "winrm"}, {5985, 5986}),
    "mssql": ({"ms-sql-s", "mssql"}, {1433}),
    "ldap": ({"ldap", "ldaps"}, {389, 636, 3268, 3269}),
    "kerberos": ({"kerberos-sec", "kerberos"}, {88}),
    "http": ({"http", "https", "http-proxy", "ssl/http"}, {80, 443, 8080, 8443}),
    "ssh": ({"ssh"}, {22}),
    "ftp": ({"ftp"}, {21}),
    "dns": ({"domain", "dns"}, {53}),
}
_IP = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]*)$")


@dataclass(frozen=True)
class Cond:
    field: str
    op: str
    value: str = ""

    def __str__(self) -> str:
        return f"{self.field}{self.op}{self.value}"


def parse_where(expr: str, types: list[str]) -> Cond:
    """``field=value``, ``!=``, ``>``, ``<``, ``~`` (contains), ``field?`` (exists), ``field!`` (missing)."""
    m = _COND.match(expr.strip()) or _UNARY.match(expr.strip())
    if not m:
        raise LootError(f"cannot read --where {expr!r}; use field=value, field!=value, field>n, "
                        "field<n, field~text, field? or field!")
    field = ALIASES.get(m["field"], m["field"])
    valid = {"id", "type"} | {f for t in (types or records.TYPES) for f in records.TYPES[t]}
    valid |= {"host_id"} if valid & {"hosts", "ip"} else set()
    if field not in valid:
        raise LootError(f"no field {m['field']!r} on {', '.join(types) or 'any type'}; "
                        f"valid: {', '.join(sorted(valid))}")
    value = m.groupdict().get("value") or ""
    return Cond(field, m["op"], value.strip().strip('"').strip("'"))


def _values(rec: dict[str, Any], field: str) -> list[Any]:
    if field == "host_id" and rec["type"] == "credential":
        return list(rec.get("hosts") or []) + list(rec.get("host_id") or [])
    if field == "host_id" and rec["type"] == "host":
        return [rec["id"]]
    value = rec.get(field)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _num(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _match(rec: dict[str, Any], cond: Cond) -> bool:
    values = _values(rec, cond.field)
    if cond.op == "?":
        return bool(values)
    if cond.op == "!":
        return not values
    if cond.op in (">", "<"):
        want = _num(cond.value)
        nums = [n for n in map(_num, values) if n is not None]
        return want is not None and any(n > want if cond.op == ">" else n < want for n in nums)
    texts = [str(v).lower() for v in values]
    if cond.op == "~":
        return any(cond.value.lower() in t for t in texts)
    wanted = {w.strip().lower() for w in cond.value.split(",")}
    if cond.field in HOST_LINKS:
        wanted = {w if w.startswith("host:") else f"host:{w}" for w in wanted}
    hit = any(t in wanted for t in texts)
    return hit if cond.op == "=" else not hit


def host_ids_named(all_records: dict[str, dict[str, Any]], name: str) -> list[str]:
    """Hosts a name points at: an IP or host id as given, else every host whose hostname is the
    name or begins with it as the first label (``dc01`` finds ``dc01.lab.local``), any case."""
    given = name.strip().lower()
    if given.startswith("host:") or _IP.match(given):
        return [given if given.startswith("host:") else f"host:{given}"]
    return sorted(r["id"] for r in all_records.values() if r["type"] == "host"
                  and any(h.lower() == given or h.lower().split(".")[0] == given for h in r.get("hostnames") or []))


def _named_hosts(cond: Cond, all_records: dict[str, dict[str, Any]]) -> Cond:
    """A host condition whose values are names, rewritten to the host ids they name."""
    if cond.field not in HOST_LINKS or cond.op not in ("=", "!="):
        return cond
    ids = [i for name in cond.value.split(",") for i in host_ids_named(all_records, name) or [name.strip()]]
    return Cond(cond.field, cond.op, ",".join(ids))


def _text_of(rec: dict[str, Any]) -> str:
    parts = [rec["id"]] + [str(v) for f in records.TYPES[rec["type"]] for v in _values(rec, f)]
    if rec["type"] == "service":
        parts += [word for word, (names, ports) in PROTOCOLS.items()
                  if str(rec.get("name", "")).lower() in names or rec.get("port") in ports]
    parts += [f"{k} {v}" for k, v in rec.get("ext", {}).items()]
    return " ".join(parts).lower()


def search(all_records: dict[str, dict[str, Any]], *, text: str = "", types: list[str] | None = None,
           where: list[str] | None = None, origin: str | None = None,
           limit: int = DEFAULT_LIMIT) -> tuple[list[str], list[dict[str, Any]], int]:
    """Returns (conditions as written, the first ``limit`` matches, total matches)."""
    types = types or []
    for t in types:
        if t not in records.TYPES:
            raise LootError(f"unknown type {t!r}; valid: {', '.join(records.TYPES)}")
    if origin and origin not in ORIGINS_HELP:
        raise LootError(f"unknown origin {origin!r}; valid: {', '.join(ORIGINS_HELP)}")
    written = [parse_where(w, types) for w in where or []]
    conds = [_named_hosts(c, all_records) for c in written]
    terms = text.lower().split()
    named = _named_secrets(all_records)
    hits, repeats = [], 0
    for rec in all_records.values():
        if types and rec["type"] not in types:
            continue
        if not all(_match(rec, c) for c in conds):
            continue
        if terms and not all(term in _text_of(rec) for term in terms):
            continue
        if origin and not any(r["origin"] == origin for c in rec["prov"].values()
                              for r in (c if isinstance(c, list) else [c])):
            continue
        if rec.get("principal") == records.UNKNOWN_USER and named & _secrets(rec):
            repeats += 1
            continue
        hits.append(rec)
    hits.sort(key=lambda r: (list(records.TYPES).index(r["type"]), r["id"]))
    described = ([f"type in {','.join(types)}"] if types else []) + [
        str(c) if c == w else f"{w} (= {c.value})" for w, c in zip(written, conds)]
    described += [f'text "{text}"'] if text else []
    described += [f"origin {origin}"] if origin else []
    described += [f"{repeats} {records.UNKNOWN_USER} password(s) not shown: each is held under a named account"
                  ] if repeats else []
    return described, hits[:limit], len(hits)


def _secrets(rec: dict[str, Any]) -> set[str]:
    return {rec[k] for k in ("secret", "secret_hash") if rec.get(k)}


def _named_secrets(all_records: dict[str, dict[str, Any]]) -> set[str]:
    """Every password and hash some credential holds under a real account."""
    return {v for r in all_records.values() if r["type"] == "credential"
            and r.get("principal") != records.UNKNOWN_USER for v in _secrets(r)}
