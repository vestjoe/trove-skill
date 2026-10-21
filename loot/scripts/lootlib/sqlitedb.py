"""A SQLite file a tool keeps, opened from its stored bytes and never written: its known rows as text."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from lootlib.errors import LootError

MAGIC = b"SQLite format 3\x00"


class DatabaseError(LootError):
    """The bytes start like a SQLite file but SQLite cannot read them."""


@dataclass
class Rendered:
    """What a database held: its tables, the reader that claimed it, and that reader's rows as text."""

    tables: dict[str, list[str]]
    reader: object | None = None
    text: bytes = b""
    notes: tuple[str, ...] = ()


def is_database(data: bytes) -> bool:
    return data.startswith(MAGIC)


def read(data: bytes, readers) -> Rendered:
    """Each table a reader asks for, one ``<table> <id>`` line per row with ``\\t<column>=<value>``
    after it. Refuses bytes SQLite cannot open; a row whose value holds a tab, anything
    ``str.splitlines`` breaks a line at, or bytes that are not UTF-8 is left out and counted."""
    image = bytearray(data)
    if image[18:20] == b"\x02\x02":
        image[18:20] = b"\x01\x01"
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(bytes(image))
        con.execute("PRAGMA trusted_schema = OFF")
        con.execute("PRAGMA query_only = ON")
        names = [n for (n,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        tables = {n: [c for (c,) in con.execute("SELECT name FROM pragma_table_info(?)", (n,))] for n in names}
        reader = next((r for r in readers if r.claims(tables)), None)
        if reader is None:
            return Rendered(tables)
        con.text_factory = bytes
        lines, skipped = [], 0
        for table, columns in reader.wanted(tables).items():
            for row in con.execute(f"SELECT {', '.join(map(_quoted, columns))} FROM {_quoted(table)} ORDER BY rowid"):
                values = [_text(v) for v in row]
                if any(v is None or "\t" in v or len(f"{v}.".splitlines()) > 1 for v in values):
                    skipped += 1
                    continue
                lines.append(f"{table} {values[0]}" + "".join(f"\t{c}={v}" for c, v in zip(columns[1:], values[1:])))
        counted = [(t, con.execute(f"SELECT count(*) FROM {_quoted(t)}").fetchone()[0])
                   for t in reader.COUNTED if t in tables]
    except sqlite3.Error as err:
        raise DatabaseError(f"not a readable SQLite database ({err})") from err
    finally:
        con.close()
    notes = []
    counted = [f"{t} ({n})" for t, n in counted if n]
    if counted:
        notes.append(f"rows in {', '.join(counted)} are not read; they are kept in the stored database")
    if skipped:
        notes.append(f"{skipped} row(s) hold a tab, a line break or bytes that are not UTF-8 text and were not "
                     "read; they are kept in the stored database")
    return Rendered(tables, reader, "".join(f"{line}\n" for line in lines).encode("utf-8"), tuple(notes))


def _quoted(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _text(value) -> str | None:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return str(value)
