"""One engagement is one ``<name>.loot`` directory; this finds it or makes it."""

from __future__ import annotations

import fcntl
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from lootlib.errors import LootError

SUFFIX = ".loot"
ENV = "LOOT_ENGAGEMENT"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class Engagement:
    root: Path

    @property
    def name(self) -> str:
        return self.root.name.removesuffix(SUFFIX)

    @property
    def raw(self) -> Path:
        return self.root / "raw"

    @property
    def records(self) -> Path:
        return self.root / "records"

    @property
    def notes(self) -> Path:
        return self.root / "notes"


def create(name: str, where: Path) -> Engagement:
    """Make ``<where>/<name>.loot``; refuses a bad name or an existing directory."""
    name = name.removesuffix(SUFFIX)
    if not _NAME.match(name):
        raise LootError(f"{name!r} is not a usable name: letters, digits, '.', '_' and '-' only")
    root = (where / f"{name}{SUFFIX}").resolve()
    if root.exists():
        raise LootError(f"{root} already exists")
    for sub in ("raw", "records", "notes"):
        (root / sub).mkdir(parents=True)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (root / "loot.json").write_text(json.dumps({"name": name, "created": created, "schema": 1}, indent=2) + "\n")
    return Engagement(root)


def _is_engagement(path: Path) -> bool:
    return path.name.endswith(SUFFIX) and (path / "loot.json").is_file()


def resolve(explicit: str | None = None, cwd: Path | None = None) -> Engagement:
    """``-e``, then ``LOOT_ENGAGEMENT``, then the cwd or a parent, then one ``*.loot`` beside you.

    Never picks between two.
    """
    cwd = (cwd or Path.cwd()).resolve()
    named = explicit or os.environ.get(ENV)
    if named:
        for candidate in (Path(named), cwd / named, cwd / f"{named}{SUFFIX}"):
            if _is_engagement(candidate):
                return Engagement(candidate.resolve())
        raise LootError(f"no engagement called {named!r} (looked for {named} and {named}{SUFFIX} in {cwd})")
    for path in (cwd, *cwd.parents):
        if _is_engagement(path):
            return Engagement(path)
    found = sorted(p for p in cwd.glob(f"*{SUFFIX}") if _is_engagement(p))
    if len(found) == 1:
        return Engagement(found[0])
    if not found:
        raise LootError(f"no engagement here ({cwd}). Create one with `loot init <name>`, or pass -e.")
    names = ", ".join(p.name for p in found)
    raise LootError(f"{len(found)} engagements in {cwd} ({names}); choose one with -e <name>")


def _refuse_links(root: Path) -> None:
    """Refuse an engagement that is or holds a symbolic link, which would send its writes elsewhere."""
    links = [root] if root.is_symlink() else []
    for here, dirs, files in os.walk(root):
        links += [Path(here, name) for name in dirs + files if Path(here, name).is_symlink()]
    if links:
        raise LootError(f"{links[0]} is a symbolic link; an engagement must hold none, so it was not opened")


@contextmanager
def locked(eng: Engagement, write: bool) -> Iterator[Engagement]:
    """Hold the engagement's lock: one writer at a time, readers wait for it to finish."""
    _refuse_links(eng.root)
    with (eng.root / ".lock").open("a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
        yield eng
