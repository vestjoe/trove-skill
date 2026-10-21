"""Open a zip at the door, so each file inside it is an input of its own.

Not a sniffing parser: ingest calls it before routing.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from lootlib.errors import LootError

MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")
_OS_METADATA = {".DS_Store", "Thumbs.db", "desktop.ini"}


class ArchiveError(LootError):
    """The archive cannot be opened, or opening it would exceed a ceiling."""


@dataclass(frozen=True)
class Member:
    name: str
    data: bytes = b""
    refused: str | None = None


def is_archive(data: bytes) -> bool:
    return data[:4] in _SIGNATURES


def is_os_metadata(name: str) -> bool:
    return name in _OS_METADATA or name.startswith("._")


def members(data: bytes) -> list[Member]:
    """Every file in the zip by name, less OS bookkeeping. Refuses the whole archive when it
    cannot be read or holds too much; refuses one member when encrypted or itself an archive."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except Exception as err:
        raise ArchiveError(f"not a zip Trove can open: {err}") from err
    files = [info for info in sorted(archive.infolist(), key=lambda info: info.filename)
             if not info.is_dir() and not is_os_metadata(PurePosixPath(info.filename).name)]
    if len(files) > MAX_MEMBERS:
        raise ArchiveError(f"holds {len(files)} files, more than the {MAX_MEMBERS} Trove opens")
    out: list[Member] = []
    total = 0
    for info in files:
        if info.flag_bits & 0x1:
            out.append(Member(info.filename, refused="encrypted; Trove holds no password for it"))
            continue
        try:
            with archive.open(info) as handle:
                body = handle.read(MAX_MEMBER_BYTES + 1)
        except Exception as err:
            out.append(Member(info.filename, refused=f"could not be read out of the archive: {err}"))
            continue
        if len(body) > MAX_MEMBER_BYTES:
            raise ArchiveError(f"{info.filename} unpacks past {MAX_MEMBER_BYTES} bytes")
        total += len(body)
        if total > MAX_TOTAL_BYTES:
            raise ArchiveError(f"unpacks past {MAX_TOTAL_BYTES} bytes in total")
        if is_archive(body):
            out.append(Member(info.filename, data=body, refused="an archive inside an archive; stored, not opened"))
            continue
        out.append(Member(info.filename, data=body))
    return out
