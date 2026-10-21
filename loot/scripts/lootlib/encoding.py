"""What Trove cites has to be UTF-8, so encoding is settled at the door."""

from __future__ import annotations

import codecs
from dataclasses import dataclass

from lootlib.errors import LootError

_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)

WINDOW = 65536


@dataclass(frozen=True)
class Normalised:
    """The bytes Trove will parse and cite, and what had to happen to get them."""

    data: bytes
    encoding: str | None = None
    text: bool = True

    @property
    def converted(self) -> bool:
        return self.encoding is not None


def normalise(data: bytes) -> Normalised:
    """UTF-8 bytes for these bytes, or a plain statement that there are none.

    Driven by the byte-order mark, never by guessing from the bytes.
    """
    if not data:
        return Normalised(data)
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            try:
                text = data[len(bom):].decode(encoding.removesuffix("-sig"))
            except UnicodeDecodeError:
                return Normalised(data, text=False)
            return Normalised(text.encode("utf-8"), encoding=encoding)
    try:
        data[:WINDOW].decode("utf-8")
    except UnicodeDecodeError:
        return Normalised(data, text=False)
    return Normalised(data)


class NotText(LootError):
    """Bytes a parser was handed are not UTF-8 text all the way through."""


def text_of(data: bytes) -> str:
    """The bytes as text, strictly; never with ``replace``, which would shift every span."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise NotText(f"not UTF-8 text: byte {err.start} is {data[err.start]:#04x} ({err.reason})") from err
