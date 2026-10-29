"""Deterministic parsers: ``sniff(data, hint) -> bool`` and ``parse(Input) -> list[record]``."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from lootlib.errors import LootError

# What wraps any tool's output: proxychains-ng, Kali's two-line zsh prompt, a rich traceback panel.
WRAPPER = re.compile(r"^(?:\[proxychains\] |┌──.*\]\s*$|└─[$#]\s*$|\s*[╭│╰])")


class ParserError(LootError):
    """A parser claimed an input and then could not read it."""


@dataclass
class Input:
    """The bytes to parse, plus what a parser needs to cite them and to join what is held.
    ``unresolved`` names references a later pass over the same import may resolve; ``unread`` holds
    lines that are not the tool's output at all, such as prose pasted around it. ``apart`` holds
    records the parser's ``apart_notice`` reports on when they are still their own after the write."""

    blob: str
    data: bytes
    source: str = ""
    known: dict[str, dict[str, Any]] = field(default_factory=dict)
    notices: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    apart: list[dict[str, Any]] = field(default_factory=list)


def registry():
    """Parsers in sniff order. ``users`` and the database readers never sniff, so they are reachable only by name."""
    from lootlib.parsers import (bloodhound, certipy, creds, masscan, naabu, netexec, nmap, nmaptext, nxcdb,
                                 responderdb, users)
    return [bloodhound, certipy, nmap, nmaptext, naabu, masscan, netexec, creds, users, nxcdb, responderdb]


def databases():
    """Readers of a SQLite file's rows, in the order they are asked whether they claim its tables."""
    from lootlib.parsers import nxcdb, responderdb
    return [nxcdb, responderdb]


def by_name(name: str):
    for module in registry():
        if module.NAME == name:
            return module
    names = ", ".join(m.NAME for m in registry())
    raise LootError(f"no parser called {name!r} (known: {names})")
