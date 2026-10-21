r"""The self-naming hash formats a credentials file may contain.

Each format states its own name in its first bytes; the table maps that token
to a type and an account.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HashFormat:
    """One line-shape. ``pattern`` is anchored and matches exactly the hash, so a
    colon inside it (a cracked AS-REP) does not split it."""

    name: str
    pattern: re.Pattern[str]
    tag: str | None = None
    name_group: str | None = None
    extras: tuple[str, ...] = ()
    claims: bool = True


_BLOB = r"[0-9a-fA-F$]+"

FORMATS: tuple[HashFormat, ...] = (
    HashFormat(
        name="krb5tgs",
        tag="$krb5tgs$",
        extras=("etype", "spn"),
        pattern=re.compile(
            r"\$krb5tgs\$(?P<etype>\d+)\$\*(?P<principal>[^$*]+)\$(?P<realm>[^$*]+)\$"
            r"(?P<spn>[^*]*)\*\$" + _BLOB
        ),
    ),
    HashFormat(
        name="krb5tgs",
        tag="$krb5tgs$",
        extras=("etype", "spn"),
        pattern=re.compile(
            r"\$krb5tgs\$(?P<etype>\d+)\$(?P<principal>[^$*]+)\$(?P<realm>[^$*]+)\$"
            r"\*(?P<spn>[^*]*)\*\$" + _BLOB
        ),
    ),
    HashFormat(
        name="krb5tgs",
        tag="$krb5tgs$",
        extras=("etype",),
        pattern=re.compile(
            r"\$krb5tgs\$(?P<etype>\d+)\$(?P<principal>[^$*]+)\$(?P<realm>[^$*]+)\$" + _BLOB
        ),
    ),
    HashFormat(
        name="krb5asrep",
        tag="$krb5asrep$",
        extras=("etype",),
        pattern=re.compile(
            r"\$krb5asrep\$(?:(?P<etype>\d+)\$)?(?P<principal>[^$@:]+)@(?P<realm>[^$:]+):" + _BLOB
        ),
    ),
    HashFormat(
        name="netntlmv1",
        extras=("challenge",),
        pattern=re.compile(
            r"(?P<principal>[^:\s]+)::(?P<realm>[^:]*):"
            r"[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:(?P<challenge>[0-9a-fA-F]{16})"
        ),
    ),
    HashFormat(
        name="netntlmv2",
        extras=("challenge",),
        pattern=re.compile(
            r"(?P<principal>[^:\s]+)::(?P<realm>[^:]*):"
            r"(?P<challenge>[0-9a-fA-F]{16}):[0-9a-fA-F]{32}:[0-9a-fA-F]+"
        ),
    ),
    HashFormat(
        name="dcc2",
        tag="$DCC2$",
        extras=("iterations",),
        pattern=re.compile(
            r"\$DCC2\$(?P<iterations>\d+)#(?P<principal>[^#]+)#[0-9a-fA-F]+"
        ),
    ),
    HashFormat(
        name="kerberos-key",
        name_group="etype",
        pattern=re.compile(
            r"(?:(?P<realm>[^:\\\r\n]+)\\)?(?P<principal>[^:\\\r\n]+):(?P<etype>aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96"
            r"|des3-cbc-sha1|des-cbc-md5|rc4_hmac):(?P<key>[0-9a-fA-F]+)"
        ),
    ),
    HashFormat(
        name="plain_password_hex",
        tag="plain_password_hex",
        pattern=re.compile(r"(?:(?P<realm>[^:\\\s]+)\\)?(?P<principal>\$MACHINE\.ACC|[^:\\\s]+\$):plain_password_hex:[0-9a-fA-F]+"),
    ),
    HashFormat(
        name="ntlm",
        pattern=re.compile(r"(?P<principal>\$MACHINE\.ACC): *[0-9a-fA-F]{32}:[0-9a-fA-F]{32}"),
    ),
    HashFormat(
        name="dpapi",
        pattern=re.compile(r"(?P<principal>dpapi_(?:machine|user)key):0x[0-9a-fA-F]+"),
    ),
    HashFormat(
        name="nlkm",
        pattern=re.compile(r"(?P<principal>NL\$KM):[0-9a-fA-F]+"),
    ),
    HashFormat(
        name="bcrypt", tag="$2", claims=False,
        pattern=re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
    ),
    HashFormat(
        name="md5crypt", tag="$1$", claims=False,
        pattern=re.compile(r"\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}"),
    ),
    HashFormat(
        name="sha256crypt", tag="$5$", claims=False,
        pattern=re.compile(r"\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}"),
    ),
    HashFormat(
        name="sha512crypt", tag="$6$", claims=False,
        pattern=re.compile(r"\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}"),
    ),
    HashFormat(
        name="yescrypt", tag="$y$", claims=False,
        pattern=re.compile(r"\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+"),
    ),
    HashFormat(
        name="argon2", tag="$argon2", claims=False,
        pattern=re.compile(r"\$argon2(?:id|i|d)\$[^\s:]+"),
    ),
)


@dataclass(frozen=True)
class TypedHash:
    """A hash a format recognised, and everything the line said about it."""

    fmt: HashFormat
    text: str
    end: int
    groups: dict[str, str]
    at: dict[str, int]

    @property
    def principal(self) -> str | None:
        return self.groups.get("principal")

    @property
    def realm(self) -> str | None:
        return self.groups.get("realm") or None

    @property
    def type_name(self) -> str:
        """What to record as ``hash_type`` — captured where the line names it."""
        if self.fmt.name_group:
            return self.groups[self.fmt.name_group]
        return self.fmt.name


def _first(line: str) -> tuple[HashFormat, re.Match[str]] | None:
    for fmt in FORMATS:
        found = fmt.pattern.match(line)
        if found is not None:
            return fmt, found
    return None


def match(line: str) -> TypedHash | None:
    """The first format whose grammar the line opens with, or ``None``; order matters."""
    hit = _first(line)
    if hit is None:
        return None
    fmt, found = hit
    groups = {k: v for k, v in found.groupdict().items() if v}
    at = {k: found.start(k) for k in groups}
    return TypedHash(fmt=fmt, text=found.group(0), end=found.end(), groups=groups, at=at)
