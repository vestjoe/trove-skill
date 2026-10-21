"""XML with byte offsets, which stdlib XML parsing does not give you.


``ElementTree`` hands back values and throws away where they were, but a parsed
field has to cite the bytes it came from. So this walks the document with
``expat``, which reports the byte index of every event, and finds an attribute's
span by scanning its own start tag — never the rest of the document, so two
ports with the same number cannot be confused.

``attrs`` holds the entity-expanded value; the span points at the raw bytes.
"""

from __future__ import annotations

import xml.parsers.expat as expat
from dataclasses import dataclass, field
from typing import Iterator

from lootlib.errors import LootError


class XmlSpanError(LootError):
    """The document is not well-formed, or an element ran off the end of it."""


@dataclass
class XmlElement:
    """One element, and where its start tag sits in the raw bytes."""

    tag: str
    attrs: dict[str, str]
    start: int
    tag_end: int
    children: list["XmlElement"] = field(default_factory=list)

    def find(self, tag: str) -> "XmlElement | None":
        return next((child for child in self.children if child.tag == tag), None)

    def all(self, tag: str) -> list["XmlElement"]:
        return [child for child in self.children if child.tag == tag]

    def get(self, name: str) -> str | None:
        return self.attrs.get(name)

    def attr_span(self, name: str, data: bytes) -> tuple[int, int] | None:
        """Byte span of one attribute's *value*, quotes excluded.


        ``None`` when the attribute is absent: the caller has nothing to cite and must
        leave the field unset.
        """
        if name not in self.attrs:
            return None
        head = data[self.start : self.tag_end]
        needle = name.encode("utf-8")
        at = 0
        while True:
            at = head.find(needle, at)
            if at < 0:
                return None
            after = at + len(needle)
            before_ok = at == 0 or head[at - 1 : at] in (b" ", b"\t", b"\n", b"\r")
            if before_ok and head[after : after + 1] == b"=":
                quote = head[after + 1 : after + 2]
                if quote in (b'"', b"'"):
                    end = head.find(quote, after + 2)
                    if end < 0:
                        return None
                    return (self.start + after + 2, self.start + end)
            at = after

    def walk(self) -> Iterator["XmlElement"]:
        yield self
        for child in self.children:
            yield from child.walk()


def _tag_end(data: bytes, start: int) -> int:
    """Index just past the ``>`` closing the start tag that begins at ``start``."""
    quote = b""
    for i in range(start, len(data)):
        char = data[i : i + 1]
        if quote:
            if char == quote:
                quote = b""
        elif char in (b'"', b"'"):
            quote = char
        elif char == b">":
            return i + 1
    raise XmlSpanError(f"start tag at byte {start} is never closed")


def parse(data: bytes) -> XmlElement:
    """Parse to a span-carrying tree. Raises ``XmlSpanError`` on anything malformed."""
    root: XmlElement | None = None
    stack: list[XmlElement] = []
    parser = expat.ParserCreate()

    def start(tag: str, attrs: dict[str, str]) -> None:
        nonlocal root
        at = parser.CurrentByteIndex
        element = XmlElement(tag=tag, attrs=dict(attrs), start=at, tag_end=_tag_end(data, at))
        if stack:
            stack[-1].children.append(element)
        else:
            root = element
        stack.append(element)

    def end(_tag: str) -> None:
        if stack:
            stack.pop()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(data, True)
    except expat.ExpatError as err:
        raise XmlSpanError(f"not well-formed XML: {err}") from err
    if root is None:
        raise XmlSpanError("document has no root element")
    return root
