"""Store an input verbatim, then route it to a parser or mark it for the agent."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from lootlib import parsers, rawstore, records, sqlitedb
from lootlib.encoding import normalise
from lootlib.engagement import Engagement
from lootlib.parsers import archive


def import_bytes(eng: Engagement, data: bytes, source: str, tool: str | None = None,
                 derived_from: str | None = None) -> list[dict[str, Any]]:
    """One input in; returns its report lines (a zip gives one per member as well).
    Raw bytes are stored before anything reads them."""
    if tool:
        parsers.by_name(tool)
    report: dict[str, Any] = {"source": source, "size": len(data), "notes": []}
    blob, is_new = rawstore.put(eng, data, source, derived_from=derived_from)
    report["blob"] = blob
    if not is_new:
        report["status"] = "already imported"
        return [report]
    if archive.is_archive(data):
        return _unpack(eng, data, blob, report, tool)
    if sqlitedb.is_database(data):
        return _from_database(eng, data, blob, report)
    norm = normalise(data)
    if not norm.text:
        rawstore.update(eng, blob, ai="binary")
        report["status"] = "stored; not text, so nothing reads it"
        return [report]
    if norm.converted:
        original = blob
        blob, _ = rawstore.put(eng, norm.data, source, derived_from=original, encoding=norm.encoding)
        rawstore.update(eng, original, ai="n/a")
        report["blob"] = blob
        report["notes"].append(f"converted from {norm.encoding} to UTF-8; the original is kept as {original}")
    parser = parsers.by_name(tool) if tool else next(
        (p for p in parsers.registry() if p.sniff(norm.data)), None)
    if parser is None:
        rawstore.update(eng, blob, ai="pending")
        report["status"] = "pending AI extraction"
        return [report]
    report["parser"] = parser.NAME
    report = _parse(eng, parser, blob, norm.data, report)
    return [report] + report.pop("_queued", [])


def _from_database(eng: Engagement, data: bytes, blob: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    """A SQLite file: the rows a reader knows, as text stored derived from it, then parsed like any file."""
    try:
        found = sqlitedb.read(data, parsers.databases())
    except sqlitedb.DatabaseError as err:
        rawstore.update(eng, blob, ai="binary")
        report["status"] = f"stored; {err}, so nothing reads it"
        return [report]
    if found.reader is None:
        rawstore.update(eng, blob, ai="binary")
        report["status"] = (f"stored; a SQLite database Trove has no reader for "
                            f"(tables: {', '.join(found.tables) or 'none'}), so nothing reads it")
        return [report]
    rawstore.update(eng, blob, ai="n/a")
    copy, _ = rawstore.put(eng, found.text, report["source"], derived_from=blob)
    report.update(blob=copy, parser=found.reader.NAME, notes=report["notes"] + list(found.notes))
    report = _parse(eng, found.reader, copy, found.text, report)
    return [report] + report.pop("_queued", [])


def _parse(eng: Engagement, parser, blob: str, data: bytes, report: dict[str, Any]) -> dict[str, Any]:
    raw = parsers.Input(blob=blob, data=data, source=report["source"], known=records.load_all(eng))
    try:
        found = parser.parse(raw)
    except parsers.ParserError as err:
        rawstore.update(eng, blob, parser=parser.NAME, ai="refused")
        report["status"] = f"refused: {err}"
        return report
    new, updated = records.put_all(eng, found)
    rawstore.update(eng, blob, parser=parser.NAME, waiting=bool(raw.unresolved))
    counts: dict[str, int] = {}
    for rec in found:
        counts[rec["type"]] = counts.get(rec["type"], 0) + 1
    before = report.setdefault("_notes", list(report["notes"]))
    report.update(status="parsed", counts=counts, new=report.get("new", 0) + new,
                  updated=report.get("updated", 0) + updated, notes=before + raw.notices,
                  _retry=bool(raw.unresolved))
    held = records.load_all(eng)
    apart = sum(records.make_id(r) in held for r in raw.apart)
    if apart:
        report["notes"] = report["notes"] + [parser.apart_notice(apart)]
    if raw.unread:
        report["notes"] = report["notes"] + [_queue_unread(eng, parser, blob, raw.unread, report)]
    return report


def _queue_unread(eng: Engagement, parser, blob: str, unread: list[str], report: dict[str, Any]) -> str:
    """Store the lines a parser found were not its tool's output as their own blob, pending
    extraction, so only they go to the model; returns the import note saying so."""
    data = "".join(f"{line}\n" for line in unread).encode("utf-8")
    source = f"{report['source']} (lines not read by {parser.NAME})"
    queued, is_new = rawstore.put(eng, data, source, derived_from=blob, ai="pending")
    if queued == blob:
        rawstore.update(eng, blob, ai="pending")
        report["status"] = "pending AI extraction"
        return f"none of its lines are {parser.NAME} output, so the whole file is left for AI extraction"
    if is_new:
        report["_queued"] = [{"source": source, "size": len(data), "blob": queued, "notes": [],
                              "status": "pending AI extraction", "derived": True}]
        return (f"{len(unread)} line(s) not read by {parser.NAME} (not its output); "
                f"queued for AI extraction as {queued[:23]}")
    state = rawstore.entry(eng, queued)["ai"]
    return f"{len(unread)} line(s) not read by {parser.NAME} are the same as {queued[:23]} ({state})"


def _unpack(eng: Engagement, data: bytes, blob: str, report: dict[str, Any], tool: str | None) -> list[dict[str, Any]]:
    """Each zip member is its own blob derived from the archive; refused members are named."""
    try:
        inside = archive.members(data)
    except archive.ArchiveError as err:
        rawstore.update(eng, blob, ai="refused")
        report["status"] = f"refused: {err}"
        return [report]
    rawstore.update(eng, blob, parser="archive")
    report["status"] = f"archive; its {len(inside)} file(s) are imported one by one below"
    out = [report]
    for member in inside:
        name = f"{report['source']}/{member.name}"
        if member.refused and not member.data:
            out.append({"source": name, "size": 0, "blob": blob, "notes": [], "status": f"refused: {member.refused}"})
        elif member.refused:
            held, _ = rawstore.put(eng, member.data, name, derived_from=blob, ai="refused")
            out.append({"source": name, "size": len(member.data), "blob": held, "notes": [],
                        "status": f"refused: {member.refused}"})
        else:
            out.extend(import_bytes(eng, member.data, name, tool, derived_from=blob))
    _read_again(eng, out)
    return out


def _read_again(eng: Engagement, reports: list[dict[str, Any]]) -> None:
    """Parse once more each input that named records not yet held, now the rest are in."""
    for report in reports:
        if report.get("_retry"):
            _parse(eng, parsers.by_name(report["parser"]), report["blob"], rawstore.read(eng, report["blob"]), report)


def _apply_earlier(eng: Engagement, reports: list[dict[str, Any]]) -> None:
    """Parse again each earlier input that named records not then held, and report the ones
    this import completed; a crack that came before its dump lands now."""
    this_import = {r.get("blob") for r in reports}
    for entry in rawstore.manifest(eng):
        if not entry.get("waiting") or entry["blob"] in this_import:
            continue
        report = {"source": entry["source"], "size": entry["size"], "blob": entry["blob"], "notes": [],
                  "parser": entry["parser"], "again": True}
        _parse(eng, parsers.by_name(entry["parser"]), entry["blob"], rawstore.read(eng, entry["blob"]), report)
        if report.get("new") or report.get("updated"):
            reports.append(dict(report, status="parsed again", notes=[]))
        reports += report.pop("_queued", [])


def _finish(eng: Engagement, reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Complete earlier inputs, then drop the bookkeeping keys a report carries while an import runs."""
    _apply_earlier(eng, reports)
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in reports]


def import_path(eng: Engagement, path: Path, tool: str | None = None) -> list[dict[str, Any]]:
    """Import one file, or every file under a directory in name order, skipping ``*.loot``
    directories and OS bookkeeping and refusing symlinks; then parse once more what
    named records not yet held."""
    if not path.is_dir():
        return _finish(eng, import_bytes(eng, path.read_bytes(), path.name, tool))
    reports: list[dict[str, Any]] = []
    for file in walk(path):
        source = f"{path.name}/{file.relative_to(path).as_posix()}"
        if file.is_symlink():
            reports.append({"source": source, "size": 0, "notes": [],
                            "status": "refused: a symbolic link; Trove reads only files inside the directory"})
            continue
        reports += import_bytes(eng, file.read_bytes(), source, tool)
    _read_again(eng, reports)
    return _finish(eng, reports)


def import_data(eng: Engagement, data: bytes, source: str = "stdin", tool: str | None = None) -> list[dict[str, Any]]:
    """Import bytes that have no file of their own, such as standard input."""
    return _finish(eng, import_bytes(eng, data, source, tool))


def walk(root: Path) -> list[Path]:
    """Files under ``root`` in name order; symlinked directories are not followed."""
    found = []
    for here, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.endswith(".loot")]
        found += [Path(here, f) for f in files if not archive.is_os_metadata(f)]
    return sorted(found, key=lambda f: f.relative_to(root).as_posix())
