"""The ``loot`` command line: one verb per subcommand, human output or ``--json``."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from lootlib import __version__, aiingest, engagement, find, ingest, notes, rawstore, records
from lootlib.errors import LootError
from lootlib.prov import ORIGINS_HELP


_CONTROL = {c: f"\\x{c:02x}" for c in [*range(0x00, 0x09), *range(0x0b, 0x20), *range(0x7f, 0xa0)]}


def safe(text: str) -> str:
    """Captured values are attacker-influenced: escape control characters so none reaches the terminal."""
    return text.translate(_CONTROL)


def _out(args: argparse.Namespace, human: str, data: Any) -> None:
    print(json.dumps(data, indent=2) if args.json else safe(human))


def cmd_init(args: argparse.Namespace) -> None:
    eng = engagement.create(args.name, Path(args.path or "."))
    human = (f"Created engagement {eng.name} at {eng.root}\n"
             f"Commands find it when run from {eng.root.parent} or inside it, "
             f"or with -e {eng.name}, or with {engagement.ENV}={eng.root}")
    _out(args, human, {"name": eng.name, "path": str(eng.root)})


def _open(args: argparse.Namespace, write: bool) -> engagement.Engagement:
    """The engagement, locked until the verb finishes."""
    return args.stack.enter_context(engagement.locked(engagement.resolve(args.engagement), write))


def cmd_import(args: argparse.Namespace) -> None:
    eng = _open(args, write=True)
    if args.path == "-":
        reports = ingest.import_data(eng, sys.stdin.buffer.read(), tool=args.tool)
    else:
        path = Path(args.path)
        if not path.exists():
            raise LootError(f"{path} does not exist")
        reports = ingest.import_path(eng, path, args.tool)
    summary = import_summary(reports, records.load_all(eng))
    lines = [f"Imported into {eng.name}: {sum(1 for r in reports if not r.get('again') and not r.get('derived'))} input(s)"]
    for r in reports:
        line = f"  {r['source']}  {r['size']} bytes  {r['status']}"
        if r.get("counts"):
            counts = ", ".join(f"{n} {t}" for t, n in r["counts"].items())
            line += f" by {r['parser']}: {counts} ({r['new']} new, {r['updated']} updated)"
        lines.append(line)
        lines += [f"    note: {n}" for n in r["notes"]]
    lines.append(f"This import: {summary['new']} new record(s), {summary['updated']} updated")
    if summary["holds"]:
        lines.append(f"{eng.name} now holds: " + ", ".join(f"{n} {t}" for t, n in summary["holds"].items()))
    if summary["refused"]:
        lines.append(f"Refused ({len(summary['refused'])}):")
        lines += [f"  {r['source']}: {r['why']}" for r in summary["refused"]]
    if summary["pending"]:
        lines.append(f"Pending AI extraction ({len(summary['pending'])}):")
        lines += [f"  {r['blob'][:23]}  {r['source']}" for r in summary["pending"]]
        lines.append("Run `loot pending`, then follow the extraction procedure." if not args.no_ai
                     else "Left for AI extraction later (--no-ai).")
    _out(args, "\n".join(lines), {"engagement": eng.name, "inputs": reports, **summary})


def import_summary(reports: list[dict[str, Any]], held: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """What this import added and changed, what the engagement now holds per type, and the
    refused and pending inputs. Per-file counts overlap, so they are never summed."""
    refused = [{"source": r["source"], "why": r["status"].removeprefix("refused: ")}
               for r in reports if r["status"].startswith("refused")]
    pending = [{"blob": r["blob"], "source": r["source"]} for r in reports if r["status"] == "pending AI extraction"]
    return {"new": sum(r.get("new", 0) for r in reports), "updated": sum(r.get("updated", 0) for r in reports),
            "holds": holds_by_type(held), "refused": refused, "pending": pending}


def holds_by_type(held: dict[str, dict[str, Any]]) -> dict[str, int]:
    holds: dict[str, int] = {}
    for rec in held.values():
        holds[rec["type"]] = holds.get(rec["type"], 0) + 1
    return dict(sorted(holds.items()))


def cmd_status(args: argparse.Namespace) -> None:
    eng = _open(args, write=False)
    counts: dict[str, int] = {}
    for rec in records.load_all(eng).values():
        counts[rec["type"]] = counts.get(rec["type"], 0) + 1
    pending = sum(1 for m in rawstore.manifest(eng) if m["ai"] == "pending")
    human = "\n".join([f"{eng.name}  {eng.root}"] + [f"  {t:<13}{n}" for t, n in counts.items()]
                      + [f"  pending AI extraction: {pending}"])
    _out(args, human, {"engagement": eng.name, "path": str(eng.root), "counts": counts, "pending": pending})


def cmd_fields(args: argparse.Namespace) -> None:
    lines = ["Types and fields (use with find --type and --where):"]
    lines += [f"  {t:<13}{', '.join(fs)}" for t, fs in records.TYPES.items()]
    lines += ["--where: field=value (comma means any of), field!=value, field>n, field<n, "
              "field~text (contains), field? (has a value), field! (has none)",
              "Also accepted: " + ", ".join(f"{a} for {f}" for a, f in find.ALIASES.items()),
              "--origin: " + "; ".join(f"{o} = {d}" for o, d in ORIGINS_HELP.items())]
    _out(args, "\n".join(lines), {"types": records.TYPES, "where_ops": ["=", "!=", ">", "<", "~", "?", "!"],
                                  "aliases": find.ALIASES, "origins": ORIGINS_HELP})


def _cited(refs: list[dict[str, Any]], shown: str) -> str:
    """Where a value came from, with the quote when it says more than the value."""
    cites = dict.fromkeys(f"{r['origin']}, {r.get('source', r['blob'][:15])}" for r in refs)
    quotes = [r["quote"] for r in refs if r["quote"] != shown]
    return f"[{'; '.join(cites)}" + (f', quote "{quotes[0][:120]}"]' if quotes else "]")


def _clipped(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 100 else f"{text[:60]}… ({len(text)} chars; --json has it whole)"


def _host_names(everything: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Each held host's id mapped to its first hostname, to show beside a link to it."""
    return {r["id"]: r["hostnames"][0] for r in everything.values() if r["type"] == "host" and r.get("hostnames")}


def _named(item: Any, names: dict[str, str]) -> str:
    return f"{item} ({names[item]})" if isinstance(item, str) and item in names else str(item)


def _field_lines(rec: dict[str, Any], names: dict[str, str] | None = None) -> list[str]:
    """One line per field; a list field gives each value its own line and its own citation.
    A link to a held host shows that host's name beside its id."""
    names = names or {}
    lines = []
    for name in records.TYPES[rec["type"]]:
        if name not in rec or name not in rec["prov"]:
            continue
        value, ref = rec[name], rec["prov"][name]
        if isinstance(value, list) and isinstance(ref, list) and len(ref) == len(value):
            for i, (item, item_ref) in enumerate(zip(value, ref)):
                label = name if i == 0 else ""
                lines.append(f"  {label:<11} {_clipped(_named(item, names))}   {_cited([item_ref], str(item))}")
            continue
        refs = ref if isinstance(ref, list) else [ref]
        shown = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
        lines.append(f"  {name:<11} {_clipped(_named(shown, names))}   {_cited(refs, shown)}")
    if rec.get("ext"):
        lines.append("  ext         " + ", ".join(f"{k}={v}" for k, v in rec["ext"].items()))
    return lines


def _services_of(host_id: str, everything: dict[str, dict[str, Any]]) -> str:
    svcs = sorted((r for r in everything.values() if r["type"] == "service" and r.get("host_id") == host_id),
                  key=lambda r: (r.get("protocol") or "", r["port"]))
    return ", ".join(f"{s['port']}/{s.get('protocol', 'tcp')} {s.get('name', '?')} ({s.get('state', '?')})"
                     for s in svcs)


def cmd_find(args: argparse.Namespace) -> None:
    eng = _open(args, write=False)
    everything = records.load_all(eng)
    conds, hits, total = find.search(everything, text=" ".join(args.text), types=args.type,
                                     where=args.where, origin=args.origin, limit=args.limit)
    lines = [f"conditions: {'; '.join(conds) or 'none (everything)'}",
             f"{total} match{'es' if total != 1 else ''}" + (f", showing {len(hits)}" if total > len(hits) else "")]
    names = _host_names(everything)
    for rec in hits:
        lines += ["", rec["id"]] + _field_lines(rec, names)
        if rec["type"] == "host" and (svcs := _services_of(rec["id"], everything)):
            lines.append(f"  services    {svcs}")
    _out(args, "\n".join(lines), {"conditions": conds, "total": total, "records": hits})


def cmd_pending(args: argparse.Namespace) -> None:
    eng = _open(args, write=False)
    rows = []
    for m in rawstore.manifest(eng):
        if m["ai"] == "pending":
            left, n = rawstore.chunks_left(eng, m)
            rows.append({"blob": m["blob"], "source": m["source"], "size": m["size"], "chunks": n,
                         "chunks_left": left})
    human = "\n".join([f"  {r['blob'][:23]}  {r['source']}  {r['size']} bytes  "
                       f"{len(r['chunks_left'])} of {r['chunks']} chunk(s) left" for r in rows]
                      ) or "Nothing is waiting for AI extraction."
    _out(args, human, {"pending": rows})


def cmd_raw(args: argparse.Namespace) -> None:
    eng = _open(args, write=False)
    entry = rawstore.entry(eng, args.blob)
    if entry["ai"] == "binary":
        raise LootError(f"{entry['source']} is not text; nothing can read it")
    data = rawstore.read(eng, entry["blob"])
    spans = rawstore.chunks(data)
    if args.chunk is None:
        left, _ = rawstore.chunks_left(eng, entry)
        if not left:
            raise LootError(f"every chunk of {entry['source']} has had a proposal; --chunk N reads one again")
        args.chunk = left[0]
    if not 1 <= args.chunk <= len(spans):
        raise LootError(f"{entry['source']} has {len(spans)} chunk(s); --chunk {args.chunk} is out of range")
    start, end = spans[args.chunk - 1]
    text = data[start:end].decode("utf-8", "replace")
    header = f"== {entry['source']}  {entry['blob'][:23]}  chunk {args.chunk}/{len(spans)}  bytes {start}-{end} of {len(data)} =="
    _out(args, f"{header}\n{text}", {"blob": entry["blob"], "source": entry["source"], "chunk": args.chunk,
                                     "chunks": len(spans), "start": start, "end": end, "text": text})


def cmd_ingest_ai(args: argparse.Namespace) -> None:
    eng = _open(args, write=True)
    text = sys.stdin.read() if args.file in (None, "-") else Path(args.file).read_text()
    result = aiingest.check(eng, args.blob, text, args.chunk)
    unchanged = result["accepted"] - result["new"] - result["updated"]
    lines = [f"chunk {result['chunk']}/{result['chunks']}: accepted {result['accepted']} record(s): "
             f"{result['new']} new, {result['updated']} updated, {unchanged} unchanged"]
    lines += [f"  dropped: {d}" for d in result["dropped"]]
    lines.append(f"next: loot raw {result['blob'][:23]} (chunk {result['remaining'][0]} of {result['chunks']})"
                 if result["remaining"] else "this file is done")
    result["holds"] = holds_by_type(records.load_all(eng))
    lines.append(f"{eng.name} now holds: " + ", ".join(f"{n} {t}" for t, n in result["holds"].items()))
    _out(args, "\n".join(lines), result)


def cmd_note(args: argparse.Namespace) -> None:
    eng = _open(args, write=True)
    data = sys.stdin.buffer.read() if args.text == "-" else args.text.encode("utf-8")
    result = notes.add(eng, data, host=args.host, tags=args.tag)
    human = f"{'Noted' if result['new'] else 'Already noted'} {result['id']} in {result['file']}"
    if result["pending"]:
        human += f"\nPending AI extraction: {result['blob'][:23]}. Follow the extraction procedure for it."
    _out(args, human, result)


def cmd_set(args: argparse.Namespace) -> None:
    eng = _open(args, write=True)
    name, sep, value = args.assignment.partition("=")
    if not sep or name != "status":
        raise LootError("set takes status=<value>: a finding's status is the one field you decide")
    result = notes.set_status(eng, args.id, value)
    _out(args, f"{result['id']}: status {result['status']} (origin you)", result)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-e", "--engagement", help="engagement name or path")
    common.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser = argparse.ArgumentParser(prog="loot", description="Store and search CTF loot, every value cited.")
    parser.add_argument("-V", "--version", action="version", version=f"Trove {__version__}")
    parser.add_argument("-e", "--engagement", dest="engagement_before", help="engagement name or path")
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("init", parents=[common], help="create <name>.loot here")
    p.add_argument("name")
    p.add_argument("--path", help="directory to create it in (default: here)")
    p.set_defaults(run=cmd_init)

    p = sub.add_parser("import", parents=[common], help="store a file, a directory or stdin and structure it")
    p.add_argument("path", help="file, directory, or - for standard input")
    p.add_argument("--tool", help="force a parser instead of detecting the format")
    p.add_argument("--no-ai", action="store_true", help="leave unparsed text for later")
    p.set_defaults(run=cmd_import)

    sub.add_parser("status", parents=[common], help="record counts and pending work").set_defaults(run=cmd_status)
    sub.add_parser("fields", parents=[common], help="types, fields and operators for find").set_defaults(run=cmd_fields)

    p = sub.add_parser("find", parents=[common], help="search records")
    p.add_argument("text", nargs="*", help="free text; every word must appear")
    p.add_argument("--type", action="append", help="record type (repeatable)")
    p.add_argument("--where", action="append", help="field condition (repeatable, ANDed)")
    p.add_argument("--origin", help="tool, ai or you")
    p.add_argument("--limit", type=int, default=find.DEFAULT_LIMIT)
    p.set_defaults(run=cmd_find)

    sub.add_parser("pending", parents=[common], help="files waiting for AI extraction").set_defaults(run=cmd_pending)

    p = sub.add_parser("raw", parents=[common], help="print one chunk of a stored text file")
    p.add_argument("blob")
    p.add_argument("--chunk", type=int, help="chunk number (default: the next without a proposal)")
    p.set_defaults(run=cmd_raw)

    p = sub.add_parser("ingest-ai", parents=[common], help="validate and store proposed records")
    p.add_argument("blob")
    p.add_argument("-f", "--file", help="proposal JSON file, or - for stdin (default)")
    p.add_argument("--chunk", type=int, help="chunk the proposal covers (default: the next without one)")
    p.set_defaults(run=cmd_ingest_ai)

    p = sub.add_parser("note", parents=[common], help="write an operator note (origin you)")
    p.add_argument("text", help="the note, or - for standard input")
    p.add_argument("--host", help="host id or IP the note is about")
    p.add_argument("--tag", action="append", help="tag (repeatable)")
    p.set_defaults(run=cmd_note)

    p = sub.add_parser("set", parents=[common], help="decide a finding's status (origin you)")
    p.add_argument("id", help="finding id, as find prints it")
    p.add_argument("assignment", help="status=<open|confirmed|failed|remediated|false_positive>")
    p.set_defaults(run=cmd_set)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse the command line and run one verb; returns the exit code."""
    args = build_parser().parse_args(argv)
    try:
        before = args.engagement_before
        if before and args.engagement and before != args.engagement:
            raise LootError(f"two engagements given, {before!r} and {args.engagement!r}; name one")
        args.engagement = args.engagement or before
        with ExitStack() as args.stack:
            args.run(args)
    except LootError as err:
        print(safe(f"loot: {err}"), file=sys.stderr)
        return 1
    return 0
