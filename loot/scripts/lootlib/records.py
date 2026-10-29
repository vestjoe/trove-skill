"""Record types, their ids, the merge rules, and one JSON file per record."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Iterable

from lootlib.engagement import Engagement
from lootlib.errors import LootError
from lootlib.ntlm import dcc2, nt_hash
from lootlib.prov import AUTHORITY, origin_of

TYPES: dict[str, tuple[str, ...]] = {
    "host": ("ip", "hostnames", "os", "state"),
    "service": ("host_id", "port", "protocol", "name", "product", "version", "banner", "state"),
    "credential": ("principal", "realm", "secret", "secret_hash", "hash_type", "state", "source", "host_id",
                   "hosts", "admin_hosts", "keys"),
    "principal": ("principal", "realm", "sid"),
    "group": ("name", "realm", "dn", "sid"),
    "share": ("host_id", "name", "permissions", "remark"),
    "finding": ("title", "description", "host_id", "service_id", "status", "suggested_status"),
    "note": ("text", "tags", "host_id"),
    "relationship": ("src_id", "kind", "dst_id"),
}
LIST_FIELDS = {("host", "hostnames"), ("note", "tags"), ("credential", "hosts"),
               ("credential", "admin_hosts"), ("credential", "host_id"), ("credential", "keys")}
KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("ip",), "service": ("host_id", "port"), "credential": ("principal",),
    "principal": ("principal",), "group": ("name",), "share": ("host_id", "name"),
    "finding": ("title",), "note": ("text",), "relationship": ("src_id", "kind", "dst_id"),
}
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_HEX = re.compile(r"[0-9A-Fa-f]+")
SALTED = {"krb5tgs", "krb5asrep", "netntlmv1", "netntlmv2",
          "aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "des3-cbc-sha1", "des-cbc-md5"}
STATE_RANK = {"found": 0, "confirmed": 1, "cracked": 2}
STATUSES = ("open", "confirmed", "failed", "remediated", "false_positive")
DECIDED = ("open", "confirmed", "remediated", "false_positive")


def _sha8(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def _ip_of(host_id: str) -> str:
    return host_id.removeprefix("host:")


UNKNOWN_USER = "(Unknown User)"


def make_id(rec: dict[str, Any]) -> str:
    """The record's identity, from its key fields only."""
    t = rec["type"]
    missing = [k for k in KEY_FIELDS[t] if rec.get(k) in (None, "", [])]
    if missing:
        raise LootError(f"{t} record has no {', '.join(missing)}")
    realm = (rec.get("realm") or "").lower()
    scoped = (lambda name: f"{realm}\\{name.lower()}" if realm else name.lower())
    if t == "host":
        return f"host:{rec['ip']}"
    if t == "service":
        return f"service:{_ip_of(rec['host_id'])}-{rec.get('protocol') or 'tcp'}-{rec['port']}"
    if t == "credential":
        secret = _password_id(rec)
        base = f"credential:{scoped(rec['principal'])}"
        return f"{base}-{_sha8(secret)}" if secret else base
    if t == "principal":
        return f"principal:{scoped(rec['principal'])}"
    if t == "group":
        return f"group:{scoped(rec['name'])}"
    if t == "share":
        return f"share:{_ip_of(rec['host_id'])}-{rec['name']}"
    if t == "finding":
        slug = _UNSAFE.sub("-", rec["title"].lower()).strip("-")[:40]
        return f"finding:{slug}-{_sha8(rec['title'] + (rec.get('host_id') or ''))}"
    if t == "note":
        return f"note:{_sha8(rec['text'])}"
    return f"rel:{rec['src_id']}-{rec['kind']}-{rec['dst_id']}"


def _password_id(rec: dict[str, Any]) -> str | None:
    """What names the password: an NT hash, else the plaintext, else an unsalted hash.
    A roasted ticket or a NetNTLM response differs every capture, so it names nothing."""
    hashed, kind = (rec.get("secret_hash") or "").lower(), rec.get("hash_type")
    if hashed and kind == "ntlm":
        return hashed
    if rec.get("secret"):
        return rec["secret"]
    return hashed if hashed and kind not in SALTED else None


_DCC2 = re.compile(r"^\$DCC2\$(\d{1,7})#([^#]+)#([0-9a-f]{32})$", re.I)
_DCC2_MAX_ITERATIONS = 1_000_000
_NT = re.compile(r"^[0-9a-f]{32}$")


def _cached_logon_of(cached: dict[str, Any], rec: dict[str, Any]) -> bool:
    """A DCC2 hash is ``rec``'s password when it derives from ``rec``'s NT hash or plaintext.
    Refuses an iteration count Windows would not write and an NT hash that is not 32 hex digits."""
    found = _DCC2.match(cached.get("secret_hash") or "")
    if not found or not 1 <= int(found[1]) <= _DCC2_MAX_ITERATIONS:
        return False
    if rec.get("hash_type") == "ntlm" and rec.get("secret_hash"):
        nt = rec["secret_hash"].lower()
    elif rec.get("secret"):
        nt = nt_hash(rec["secret"])
    else:
        return False
    return bool(_NT.match(nt)) and dcc2(nt, found[2], int(found[1])) == found[3].lower()


def _password_keys(rec: dict[str, Any]) -> set[str]:
    """Every name this credential's password goes by; two credentials sharing one hold the same password."""
    keys = set()
    if rec.get("secret_hash"):
        keys.add("hash:" + rec["secret_hash"].lower())
    if rec.get("secret"):
        keys |= {"plain:" + rec["secret"], "hash:" + nt_hash(rec["secret"])}
    return keys


def new(type_name: str, **fields: Any) -> dict[str, Any]:
    """An empty record of a known type, with any fields given (values only, no citations)."""
    if type_name not in TYPES:
        raise LootError(f"unknown record type {type_name!r} (known: {', '.join(TYPES)})")
    rec: dict[str, Any] = {"type": type_name, "prov": {}, "ext": {}}
    rec.update(fields)
    return rec


def is_hex(value: Any) -> bool:
    """A plain hex hash (NT, LM): one value in any letter case."""
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def set_field(rec: dict[str, Any], name: str, value: Any, citation: Any) -> None:
    """Set a core field and its citation together; a value without one is refused."""
    if name not in TYPES[rec["type"]]:
        raise LootError(f"{rec['type']} has no field {name!r}")
    if citation is None:
        raise LootError(f"{rec['type']}.{name} has no citation")
    if name == "secret_hash" and is_hex(value):
        value = value.lower()
    rec[name] = value
    rec["prov"][name] = citation


def add_to_ext_list(rec: dict[str, Any], key: str, value: Any) -> None:
    """Append ``value`` to the list ``rec["ext"][key]``, starting the list if absent; a value
    already in it is not added again."""
    held = rec["ext"].setdefault(key, [])
    if value not in held:
        held.append(value)


def _path(eng: Engagement, rid: str):
    readable = _UNSAFE.sub("_", rid.split(":", 1)[1])[:80]
    return eng.records / rid.split(":", 1)[0] / f"{readable}-{_sha8(rid)}.json"


def load_all(eng: Engagement) -> dict[str, dict[str, Any]]:
    out = {}
    for path in sorted(eng.records.glob("*/*.json")):
        rec = json.loads(path.read_text())
        if rec["type"] == "credential" and isinstance(rec.get("host_id"), str):
            rec["host_id"], rec["prov"]["host_id"] = [rec["host_id"]], [rec["prov"]["host_id"]]
        out[rec["id"]] = rec
    return out


def merge(old: dict[str, Any], new_rec: dict[str, Any]) -> bool:
    """Fold ``new_rec`` into ``old``: you > tool > ai, then the credential rank rules between
    values of equal authority; later wins at equal authority; lists union."""
    changed = False
    for name in TYPES[old["type"]]:
        if name not in new_rec["prov"]:
            continue
        value, cite = new_rec[name], new_rec["prov"][name]
        if (old["type"], name) in LIST_FIELDS:
            have = list(old.get(name) or [])
            refs = list(old["prov"].get(name) or [])
            for v, c in zip(value, cite):
                if v not in have:
                    have.append(v)
                    refs.append(c)
                    changed = True
            old[name], old["prov"][name] = have, refs
            continue
        held = old["prov"].get(name)
        rank = AUTHORITY[origin_of(cite)] - AUTHORITY[origin_of(held)] if held else 0
        if rank < 0 or (rank == 0 and old["type"] == "credential" and _keeps_old(old, new_rec, name)):
            continue
        if old.get(name) != value or old["prov"].get(name) != cite:
            old[name], old["prov"][name] = value, cite
            changed = True
    for key, value in new_rec.get("ext", {}).items():
        if old["ext"].get(key) != value:
            old["ext"][key] = value
            changed = True
    return changed


def _keeps_old(old: dict[str, Any], new_rec: dict[str, Any], name: str) -> bool:
    """A weaker state never replaces a stronger one, and an NT hash is not replaced by another kind."""
    if name == "state" and name in old:
        return STATE_RANK.get(new_rec[name], 0) < STATE_RANK.get(old[name], 0)
    if name in ("secret_hash", "hash_type") and old.get("hash_type") == "ntlm":
        return new_rec.get("hash_type") != "ntlm"
    if name == "realm" and "." in (old.get(name) or ""):
        return "." not in (new_rec.get(name) or "")
    return False


def _long_realms(held: dict[str, dict[str, Any]]) -> dict[str, str]:
    """A short (NetBIOS) realm mapped to the one held DNS realm whose first label it is:
    ``essos`` to ``essos.local``. Two candidates map it to neither."""
    long = {r for rec in held.values() if (r := (rec.get("realm") or "").lower()) and "." in r}
    out: dict[str, str] = {}
    for realm in {r.split(".")[0] for r in long}:
        fits = [r for r in long if r.split(".")[0] == realm]
        if len(fits) == 1:
            out[realm] = fits[0]
    return out


def _same_credentials(held: dict[str, dict[str, Any]]) -> list[list[str]]:
    """Ids of credentials that are one account's one password, in groups of two or more.
    An account's captures whose password is unknown are one group, joined to the account's
    password once exactly one is known."""
    parent: dict[str, str] = {}

    def root(rid: str) -> str:
        while parent[rid] != rid:
            rid = parent[rid]
        return rid

    long_names = _long_realms(held)
    by_key: dict[tuple[str, str, str], str] = {}
    accounts: dict[tuple[str, str], list[str]] = {}
    for rid, rec in held.items():
        if rec["type"] != "credential":
            continue
        parent[rid] = rid
        realm = (rec.get("realm") or "").lower()
        account = (long_names.get(realm, realm), rec["principal"].lower())
        accounts.setdefault(account, []).append(rid)
        keys = _password_keys(rec) | (set() if _password_id(rec) else {"unknown"})
        for key in keys:
            other = by_key.setdefault((*account, key), rid)
            parent[root(rid)] = root(other)
    for rids in accounts.values():
        for cached in (r for r in rids if held[r].get("hash_type") == "dcc2"):
            for rid in rids:
                if _cached_logon_of(held[cached], held[rid]):
                    parent[root(cached)] = root(rid)
    for account, rids in accounts.items():
        known = {root(r) for r in rids if _password_id(held[r])}
        unknown = by_key.get((*account, "unknown"))
        if unknown and len(known) == 1:
            parent[root(unknown)] = known.pop()
    for rid, rec in held.items():
        if rec["type"] != "credential" or rec.get("realm") or rec.get("host_id"):
            continue
        owners = {root(o) for (realm, name), rids in accounts.items()
                  if realm and name == rec["principal"].lower()
                  for o in rids if _same_dump_line(rec, held[o])}
        if len(owners) == 1:
            parent[root(rid)] = owners.pop()
    groups: dict[str, list[str]] = {}
    for rid in parent:
        groups.setdefault(root(rid), []).append(rid)
    return [sorted(g) for g in groups.values() if len(g) > 1]


def _same_dump_line(bare: dict[str, Any], held: dict[str, Any]) -> bool:
    """A dump line saved with no domain or host is ``held`` when it has the same hash and RID.

    The empty password's hash never joins: every machine's disabled accounts hold it."""
    rids = {r for r in (bare["ext"].get("rid"), held.get("ext", {}).get("rid")) if r}
    shared = _password_keys(bare) & _password_keys(held) - {"hash:" + nt_hash(""), "plain:"}
    return bool(shared) and len(rids) < 2


def put_all(eng: Engagement, recs: Iterable[dict[str, Any]]) -> tuple[int, int]:
    """Write records, merging into any with the same id; returns (new, updated)."""
    existing = load_all(eng)
    touched: dict[str, dict[str, Any]] = {}
    added: set[str] = set()
    changed: set[str] = set()
    for rec in recs:
        rec = dict(rec, id=make_id(rec))
        current = touched.get(rec["id"]) or existing.get(rec["id"])
        if current is None:
            touched[rec["id"]] = rec
            added.add(rec["id"])
        elif merge(current, rec):
            if rec["id"] in existing:
                changed.add(rec["id"])
            touched[rec["id"]] = current
    held = {**existing, **touched}
    for group in _same_credentials(held):
        olds = [rid for rid in group if rid in existing]
        merged = held[group[0]]
        for rid in group[1:]:
            merge(merged, held[rid])
        merged["id"] = make_id(merged)
        if added & set(group):
            added -= set(group)
            changed -= set(group)
            (changed if olds else added).add(olds[0] if olds else merged["id"])
        for rid in group:
            if rid != merged["id"]:
                touched.pop(rid, None)
                _path(eng, rid).unlink(missing_ok=True)
        touched[merged["id"]] = merged
    for rec in touched.values():
        path = _path(eng, rec["id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        ordered = {"id": rec["id"], "type": rec["type"],
                   **{k: rec[k] for k in TYPES[rec["type"]] if k in rec},
                   "prov": rec["prov"], "ext": rec.get("ext", {})}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(ordered, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    return len(added), len(changed)
