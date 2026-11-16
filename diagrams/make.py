#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Draw the documentation diagrams from Trove runs on the GOAD corpus.

Writes docs/assets/diagrams/<name>-light.svg and -dark.svg; with --check it
compares them instead and exits 1 when one differs. Stops when a run no longer
prints a line a diagram shows.
"""
import contextlib
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "loot/scripts"))
from lootlib import cli  # noqa: E402

GOAD = ROOT / "tests/corpus/goad"
OUT = ROOT / "docs/assets/diagrams"
W, M = 1376, 32
MONO_PX, LH, PAD = 26, 38, 26
MONO_W = MONO_PX * 0.61
SANS = "Inter, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'JetBrains Mono', Menlo, Consolas, 'DejaVu Sans Mono', 'Liberation Mono', 'Courier New', monospace"

TERM = {"bg": "#241E19", "edge": "#1A1613", "text": "#E9E2D3", "dim": "#9A8F80",
        "gold": "#F2C14E", "pale": "#FFE9A8", "teal": "#7CC7BC", "rust": "#F0916A", "plum": "#CDA8DC"}
THEMES = {
    "light": {"bg": "#FFFDF7", "panel": "#FBF4E2", "border": "#E8DCBC", "ink": "#1A1613", "grey": "#6E655C",
              "amber": "#D9A227", "bronze": "#8C6A1F", "teal": "#2F7D74", "plum": "#7A4E8C", "rust": "#B4532A",
              **{"t_" + k: v for k, v in TERM.items()}},
    "dark": {"bg": "#211C18", "panel": "#2B241E", "border": "#4A3F33", "ink": "#F3EBDD", "grey": "#B8AD9C",
             "amber": "#E6B43C", "bronze": "#E0B860", "teal": "#6CC4B8", "plum": "#C39BD6", "rust": "#E8875C",
             **{"t_" + k: v for k, v in TERM.items()}, "t_bg": "#14110E", "t_edge": "#4A3F33"},
}
ORIGIN = {"tool": "amber", "ai": "teal", "you": "plum"}

PROPOSAL = {"records": [
    {"type": "finding", "fields": {
        "title": {"value": "Upload page accepts .asp files",
                  "evidence": "has an upload page at /upload that accepts .asp files"},
        "description": {"value": "A web shell is possible from the upload page.",
                        "evidence": "a web shell is possible from there"},
        "host": {"value": "192.168.56.22", "evidence": "castelblack (192.168.56.22)"}}},
    {"type": "share", "fields": {
        "host": {"value": "192.168.56.22", "evidence": "castelblack (192.168.56.22)"},
        "name": {"value": "all", "evidence": "the `all` share is readable and writable"},
        "permissions": {"value": "READ, WRITE", "evidence": "readable and writable"}}},
]}

TOOLS = [
    ("Scans", "amber", [("nmap", "hosts, services"), ("masscan", "hosts, services, banners"),
                        ("naabu", "services"), ("nuclei", "findings, services")]),
    ("Logins", "amber", [("NetExec", "credentials, findings, shares"),
                         ("NetExec database", "hosts, credentials, shares"),
                         ("Hydra", "credentials, hosts, services"), ("kerbrute", "credentials, accounts")]),
    ("Hashes", "amber", [("secretsdump", "NT hashes, Kerberos keys, cached logons"),
                         ("GetUserSPNs and GetNPUsers", "kerberoast and AS-REP hashes, group memberships"),
                         ("Responder", "NetNTLM hashes, passwords")]),
    ("Directory", "amber", [("BloodHound", "accounts, groups, findings"), ("certipy", "findings"),
                            ("user lists", "accounts")]),
    ("Cracked passwords", "amber", [("hashcat", "cracked passwords"), ("John the Ripper", "cracked passwords")]),
    ("Notes and other files", "teal", [("", "The agent reads them and makes records with origin ai.")]),
]
RECORD_TYPES = "host, service, credential, principal, group, share, finding, note, relationship"


class Engagement:
    """A temporary engagement that runs loot verbs in-process; refuses a failing verb."""

    def __init__(self, stack):
        self.dir = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        self("init", "demo")

    def __call__(self, *argv):
        out, cwd = io.StringIO(), os.getcwd()
        os.chdir(self.dir)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main([str(a) for a in argv])
        finally:
            os.chdir(cwd)
        if code:
            raise SystemExit(f"loot {' '.join(map(str, argv))} failed")
        return out.getvalue()


def line_with(text, *parts):
    """The first line of text that holds every part; refuses when none does."""
    for line in text.splitlines():
        if all(p in line for p in parts):
            return line
    raise SystemExit(f"no line holds {parts!r}")


def field_lines(text, *names):
    """A find result's header and the named field lines with their continuations, '  ...' for gaps."""
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines) if l and not l.startswith((" ", "conditions:")) and "match" not in l)
    out, keep, skipped = [lines[start]], False, False
    for line in lines[start + 1:]:
        if not line.strip():
            break
        head = line[:14].strip()
        if head:
            keep = head in names
            if not keep:
                skipped = True
        if keep:
            if skipped and len(out) > 1:
                out.append("  ...")
            skipped = False
            out.append(line)
    missing = [n for n in names if not any(l[:14].strip() == n for l in out)]
    if missing:
        raise SystemExit(f"find printed no {missing!r}")
    return out + (["  ..."] if skipped else [])


def runs():
    """Run every scenario the diagrams show and return the text each one printed."""
    r = {}
    with contextlib.ExitStack() as stack:
        e = Engagement(stack)
        e("import", GOAD / "scans/goad-full.xml")
        e("import", GOAD / "nxc/nxc-cred-check.txt")
        r["host"] = e("find", "--where", "ip=192.168.56.22", "--type", "host")
        cred = next((e.dir / "demo.loot/records/credential").glob("north.sevenkingdoms.local_rickon.stark_*"))
        r["cred"] = json.loads(cred.read_text())
        r["tool_finding"] = e("find", "--type", "finding", "--where", "host=castelblack")
        note = re.search(r"cat > notes/castelblack.md <<'EOF'\n(.*?\n)EOF\n",
                         (ROOT / "docs/tutorial.md").read_text(), re.S).group(1)
        (e.dir / "notes").mkdir()
        (e.dir / "notes/castelblack.md").write_text(note)
        e("import", "notes/castelblack.md")
        r["note"] = note
        r["blob"] = "sha256:" + hashlib.sha256(note.encode()).hexdigest()[:16]
        (e.dir / "proposal.json").write_text(json.dumps(PROPOSAL))
        e("raw", r["blob"])
        r["ingest"] = e("ingest-ai", r["blob"], "-f", "proposal.json")
        r["ai_finding"] = e("find", "Upload page", "--type", "finding")
        r["finding_id"] = line_with(r["ai_finding"], "finding:").split()[0]
        r["set"] = e("set", r["finding_id"], "status=confirmed")
        r["you_finding"] = e("find", "Upload page", "--type", "finding")

        e = Engagement(stack)
        e("import", GOAD / "scans/goad-full.nmap")
        r["service"] = e("find", "--type", "service", "--where", "host=castelblack", "--where", "port=80")

        e = Engagement(stack)
        e("import", GOAD / "scans/goad-full.xml")
        r["scan_first"] = e("import", GOAD / "dumps/secretsdump-castelblack.txt")
        r["goadmin"] = e("find", "goadmin", "--type", "credential")

        e = Engagement(stack)
        r["dump_first"] = e("import", GOAD / "dumps/secretsdump-castelblack.txt")
        r["parsed_again"] = e("import", GOAD / "scans/goad-full.xml")
        if e("find", "goadmin", "--type", "credential") != r["goadmin"]:
            raise SystemExit("goadmin differs between the two import orders")
    return r


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def wrap(text, width, indent=0):
    """Split a line into (start, end) pieces at spaces, preferring column gaps; refuses a word that can't fit."""
    spans, a = [], 0
    while len(text) - a > (width if not spans else width - indent):
        room = width if not spans else width - indent
        window = text[a:a + room + 1]
        cuts = [m.start() for m in re.finditer(r"(?<=\S) +", window)]
        gaps = [m.start() for m in re.finditer(r"(?<=\S) {2,}", window) if m.start() >= room * 0.25]
        if not cuts:
            raise SystemExit(f"can't wrap {text[a:]!r} at {room}")
        cut = (gaps or cuts)[-1]
        spans.append((a, a + cut))
        a += cut + len(window[cut:]) - len(window[cut:].lstrip(" "))
    return spans + [(a, len(text))]


def wrapped(text, width):
    return [text[a:b] for a, b in wrap(text, width)]


def paint(line, spans, marks, seen):
    """Colour runs per piece of one line for every place a marked substring occurs in it."""
    where = []
    for s, c in marks:
        at = line.find(s)
        while at >= 0:
            if all(at >= b or at + len(s) <= a for a, b, _ in where):
                where.append((at, at + len(s), c))
                seen.add(s)
            at = line.find(s, at + len(s))
    pieces = []
    for a, b in spans:
        runs, i = [], a
        for x, y, c in sorted(where):
            x, y = max(x, a), min(y, b)
            if x < y:
                runs += [(line[i:x], None), (line[x:y], c)]
                i = y
        pieces.append(runs + [(line[i:b], None)])
    return pieces


class Svg:
    def __init__(self, theme):
        self.t, self.parts, self.y = THEMES[theme], [], M

    def c(self, key):
        return self.t.get(key, key)

    def add(self, s):
        self.parts.append(s)

    def text(self, x, y, s, size=28, bold=False, colour="ink", anchor="start", mono=False):
        weight = ' font-weight="700"' if bold else ""
        fam = "m" if mono else "s"
        self.add(f'<text class="{fam}" x="{x:.0f}" y="{y:.0f}" font-size="{size}" text-anchor="{anchor}"'
                 f'{weight} fill="{self.c(colour)}" xml:space="preserve">{esc(s)}</text>')

    def rich(self, x, y, runs, size=28, bold=False):
        weight = ' font-weight="700"' if bold else ""
        body = "".join(f'<tspan fill="{self.c(c)}">{esc(t)}</tspan>' if c else esc(t) for t, c in runs if t)
        self.add(f'<text class="s" x="{x:.0f}" y="{y:.0f}" font-size="{size}"{weight} fill="{self.c("ink")}"'
                 f' xml:space="preserve">{body}</text>')

    def term(self, x, y, w, title, lines, marks=(), indent=0):
        """Terminal card; lines wrap to the card, continuation pieces start indent columns in."""
        cols = int((w - 2 * PAD) / MONO_W)
        rows, seen = [], set()
        for line in lines:
            spans = wrap(line, cols, indent)
            dim = line.strip() == "..."
            for k, runs in enumerate([[(line, "t_dim")]] if dim else paint(line, spans, marks, seen)):
                rows.append((runs, indent if k else 0))
        if missing := [s for s, _ in marks if s not in seen]:
            raise SystemExit(f"{title or lines[0]!r} shows none of {missing!r}")
        top = 54 if title else 14
        h = top + len(rows) * LH + 18
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{self.c("t_bg")}"'
                 f' stroke="{self.c("t_edge")}" stroke-width="3"/>')
        if title:
            self.add(f'<path d="M{x + 2} {y + 50} H{x + w - 2}" stroke="{self.c("t_edge")}" stroke-width="2"/>')
            for i, dot in enumerate(("t_rust", "t_gold", "amber")):
                self.add(f'<circle cx="{x + 28 + i * 24}" cy="{y + 25}" r="7" fill="{self.c(dot)}"/>')
            self.add(f'<text class="m" x="{x + 104}" y="{y + 34}" font-size="{MONO_PX}" fill="{self.c("t_dim")}"'
                     f' xml:space="preserve">{esc(title)}</text>')
        for i, (runs, ind) in enumerate(rows):
            body = "".join(f'<tspan fill="{self.c(c)}">{esc(t)}</tspan>' if c else esc(t) for t, c in runs if t)
            self.add(f'<text class="m" x="{x + PAD + ind * MONO_W:.0f}" y="{y + top + LH * (i + 1) - 10}"'
                     f' font-size="{MONO_PX}" fill="{self.c("t_text")}" xml:space="preserve">{body}</text>')
        return h

    def panel(self, x, y, w, title, rows):
        """A light card of mono rows, each a list of (text, colour) runs, under a bold title."""
        h = 70 + len(rows) * LH + 16
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{self.c("panel")}"'
                 f' stroke="{self.c("border")}" stroke-width="3"/>')
        self.text(x + PAD, y + 46, title, MONO_PX, True, mono=True)
        for i, runs in enumerate(rows):
            body = "".join(f'<tspan fill="{self.c(c)}">{esc(t)}</tspan>' if c else esc(t) for t, c in runs if t)
            self.add(f'<text class="m" x="{x + PAD}" y="{y + 70 + LH * (i + 1) - 10}" font-size="{MONO_PX}"'
                     f' fill="{self.c("ink")}" xml:space="preserve">{body}</text>')
        return h

    def arrow(self, x1, y1, x2, y2, colour="amber", dashed=False):
        da = ' stroke-dasharray="12 10"' if dashed else ""
        self.add(f'<path d="M{x1:.0f} {y1:.0f} L{x2:.0f} {y2:.0f}" stroke="{self.c(colour)}" stroke-width="5"'
                 f' stroke-linecap="round"{da} marker-end="url(#{colour})"/>')

    def pill(self, x, y, s, colour, anchor="start"):
        w = len(s) * MONO_W + 36
        x0 = x - w if anchor == "end" else x
        self.add(f'<rect x="{x0:.0f}" y="{y}" width="{w:.0f}" height="44" rx="22" fill="{self.c(colour)}"/>')
        rgb = [int(self.c(colour)[i:i + 2], 16) for i in (1, 3, 5)]
        ink = "#1A1613" if 0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2] > 150 else "#FFFDF7"
        self.text(x0 + w / 2, y + 31, s, MONO_PX, True, ink, "middle", mono=True)

    def file(self, x, y, s, colour="border"):
        w = len(s) * MONO_W + 40
        self.add(f'<rect x="{x - w / 2:.0f}" y="{y}" width="{w:.0f}" height="56" rx="12" fill="{self.c("panel")}"'
                 f' stroke="{self.c(colour)}" stroke-width="3"/>')
        self.text(x, y + 37, s, MONO_PX, True, "ink", "middle", mono=True)
        return 56

    def heading(self, x, y, s, origin=None):
        self.text(x, y, s, 30, True)
        if origin:
            self.pill(W - M, y - 32, origin, ORIGIN[origin], "end")

    def render(self):
        h = self.y + M
        marks = "".join(
            f'<marker id="{k}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4"'
            f' orient="auto"><path d="M0,0 L10,5 L0,10 Z" fill="{self.c(k)}"/></marker>'
            for k in ("amber", "teal", "rust", "plum", "bronze"))
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {h}" width="{W}" height="{h}">\n'
                f'<defs><style>.s{{font-family:{SANS}}} .m{{font-family:{MONO}}}</style>{marks}</defs>\n'
                f'<rect x="1.5" y="1.5" width="{W - 3}" height="{h - 3}" rx="18" fill="{self.c("bg")}"'
                f' stroke="{self.c("border")}" stroke-width="3"/>\n' + "\n".join(self.parts) + "\n</svg>\n")


def merge(s, r):
    xml = (GOAD / "scans/goad-full.xml").read_text().splitlines()
    at = next(i for i, l in enumerate(xml) if 'addr="192.168.56.22"' in l)
    xml_lines = [xml[at].strip(), xml[at + 1].strip(), xml[at + 2].strip()]
    nxc = line_with((GOAD / "nxc/nxc-cred-check.txt").read_text(), "192.168.56.22", "[*]")
    w = W - 2 * M
    s.y += s.term(M, s.y, w, "goad-full.xml  (nmap)", xml_lines,
                  [("192.168.56.22", "t_gold"), ("castelblack.north.sevenkingdoms.local", "t_gold")]) + 20
    s.y += s.term(M, s.y, w, "nxc-cred-check.txt  (NetExec)", [nxc],
                  [("192.168.56.22", "t_teal"), ("name:CASTELBLACK", "t_teal"),
                   ("Windows 10 / Server 2019 Build 17763 x64", "t_teal")], indent=4) + 18
    s.arrow(M + 60, s.y, M + 60, s.y + 84)
    s.rich(M + 100, s.y + 54, [("Trove stores both files under ", None), ("raw/", "bronze"), (" and makes one host record", None)],
           28, True)
    s.y += 104
    host = field_lines(r["host"], "ip", "hostnames", "os", "state")
    s.y += s.term(M, s.y, w, "$ loot find --where ip=192.168.56.22 --type host", host,
                  [("[tool, goad-full.xml]", "t_gold"), ("[tool, nxc-cred-check.txt]", "t_teal")], indent=14)


def quotes(s, r):
    raw = (GOAD / "nxc/nxc-cred-check.txt").read_text().splitlines()
    line = raw[7]
    prov = r["cred"]["prov"]
    if "rickon.stark:Winter2022" not in line:
        raise SystemExit("line 8 of nxc-cred-check.txt moved")
    w = W - 2 * M
    s.y += s.term(M, s.y, w, "nxc-cred-check.txt, line 8", [line],
                  [("[+]", "t_rust"), (prov["realm"]["quote"], "t_gold"),
                   (prov["principal"]["quote"], "t_teal"), (prov["secret"]["quote"], "t_plum")]) + 20
    s.arrow(W / 2, s.y, W / 2, s.y + 60)
    s.y += 74
    panel = {"realm": "bronze", "principal": "teal", "secret": "plum", "state": "rust"}
    rows = []
    for f, c in panel.items():
        rows.append([(f"{f:<11} ", c), (r["cred"][f], None)])
        rows.append([(" " * 12, None), (f'quote "{prov[f]["quote"]}"', c)])
    s.y += s.panel(M, s.y, w, r["cred"]["id"], rows)


def parser_agent(s, r):
    w = W - 2 * M
    s.heading(M, s.y + 34, "A parser reads tool output", "tool")
    s.y += 62
    nmap = (GOAD / "scans/goad-full.nmap").read_text().splitlines()
    at = next(i for i, l in enumerate(nmap) if l.startswith("Nmap scan report for castelblack"))
    port = next(i for i in range(at, at + 20) if nmap[i].startswith("80/tcp"))
    s.y += s.term(M, s.y, w, "goad-full.nmap", [nmap[at], "...", nmap[port]],
                  [("192.168.56.22", "t_gold"), ("80/tcp", "t_gold"), ("Microsoft IIS httpd 10.0", "t_gold")]) + 14
    s.arrow(W / 2, s.y, W / 2, s.y + 56)
    s.y += 70
    svc = field_lines(r["service"], "host_id", "port", "protocol", "name", "banner", "state")
    s.y += s.term(M, s.y, w, "$ loot find --type service --where host=castelblack --where port=80", svc,
                  [("[tool, goad-full.nmap", "t_gold")], indent=14) + 60
    s.add(f'<path d="M{M} {s.y - 26} H{W - M}" stroke="{s.c("border")}" stroke-width="3"/>')
    s.heading(M, s.y + 34, "The agent reads your note", "ai")
    s.y += 62
    note = r["note"].rstrip("\n").splitlines()
    s.y += s.term(M, s.y, w, "notes/castelblack.md", note,
                  [("castelblack (192.168.56.22)", "t_teal"),
                   ("has an upload page at /upload that accepts .asp files", "t_teal"),
                   ("the `all` share is readable and writable", "t_teal"), ("looks possible", "t_rust")],
                  indent=2) + 14
    s.arrow(W / 2, s.y, W / 2, s.y + 56, "teal")
    s.y += 70
    desc = PROPOSAL["records"][0]["fields"]["description"]
    s.y += s.term(M, s.y, w, "the agent's proposal, one field",
                  [f'"description": {{"value": "{desc["value"]}",',
                   f'                "evidence": "{desc["evidence"]}"}}'],
                  [("is possible", "t_rust")], indent=16) + 14
    s.arrow(W / 2, s.y, W / 2, s.y + 56, "teal")
    s.y += 70
    rep = [l for l in r["ingest"].splitlines() if not l.startswith("demo now holds")]
    s.y += s.term(M, s.y, w, f"$ loot ingest-ai {r['blob']} -f proposal.json", rep,
                  [("accepted 2 record(s)", "t_teal"), ("dropped:", "t_rust")], indent=4) + 46
    s.rich(M, s.y, [("The file says ", None), ('"looks possible"', "rust"),
                    (", so Trove drops the quote ", None), ('"is possible"', "rust"), (".", None)], 30, True)
    s.y += 8


def import_order(s, r):
    half = (W - 2 * M - 32) / 2
    lx, rx = M, M + half + 32
    lc, rc = lx + half / 2, rx + half / 2
    s.heading(lx, s.y + 34, "Scan first")
    s.text(rx, s.y + 34, "Dump first", 30, True)
    s.y += 62
    dump = "secretsdump-castelblack.txt"
    first = line_with(r["scan_first"], dump)
    wait = line_with(r["dump_first"], "note:", "CASTELBLACK")
    again = line_with(r["parsed_again"], dump, "parsed again")
    ly = ry = s.y
    ly += s.file(lc, ly, "goad-full.xml") + 8
    s.arrow(lc, ly, lc, ly + 44)
    ly += 56
    ly += s.file(lc, ly, dump) + 8
    s.arrow(lc, ly, lc, ly + 44)
    ly += 56
    ly += s.term(lx, ly, half, "", [first.strip()], [("parsed by creds", "t_gold")], indent=2)
    ry += s.file(rc, ry, dump, "bronze") + 8
    s.arrow(rc, ry, rc, ry + 44, "bronze", dashed=True)
    s.text(rc + 24, ry + 34, "waits", 28, True, "bronze")
    ry += 56
    ry += s.term(rx, ry, half, "", [wait.strip()], [("note:", "t_rust")], indent=2) + 8
    s.arrow(rc, ry, rc, ry + 44)
    ry += 56
    ry += s.file(rc, ry, "goad-full.xml") + 8
    s.arrow(rc, ry, rc, ry + 44)
    s.text(rc + 24, ry + 34, "read again", 28, True, "bronze")
    ry += 56
    ry += s.term(rx, ry, half, "", [again.strip()], [("parsed again", "t_gold")], indent=2)
    bottom = max(ly, ry) + 24
    s.arrow(lc, ly + 8, lc, bottom + 64)
    s.arrow(rc, ry + 8, rc, bottom + 64)
    s.text(W / 2, bottom + 46, "Both orders give this record", 28, True, "bronze", "middle")
    s.y = bottom + 80
    goadmin = field_lines(r["goadmin"], "principal", "host_id")
    s.y += s.term(M, s.y, W - 2 * M, "$ loot find goadmin --type credential", goadmin,
                  [('quote "CASTELBLACK"', "t_gold")], indent=14)


def tool_map(s, r):
    gap = 24
    cw = (W - 2 * M - gap) / 2
    inner = cw - 64
    for row in range(3):
        cards = TOOLS[row * 2:row * 2 + 2]
        heights = []
        for title, edge, items in cards:
            h = 70
            for name, recs in items:
                h += (40 if name else 0) + 36 * len(wrapped(recs, int(inner / (26 * 0.56)))) + 12
            heights.append(h + 6)
        h = max(heights)
        for k, (title, edge, items) in enumerate(cards):
            x = M + k * (cw + gap)
            s.add(f'<rect x="{x:.0f}" y="{s.y}" width="{cw:.0f}" height="{h}" rx="14" fill="{s.c(edge)}"/>')
            s.add(f'<rect x="{x + 10:.0f}" y="{s.y}" width="{cw - 10:.0f}" height="{h}" rx="12"'
                  f' fill="{s.c("panel")}"/>')
            s.add(f'<rect x="{x:.0f}" y="{s.y}" width="{cw:.0f}" height="{h}" rx="14" fill="none"'
                  f' stroke="{s.c("border")}" stroke-width="3"/>')
            s.text(x + 36, s.y + 48, title, 30, True, s.t["bronze"] if edge == "amber" else s.t["teal"])
            y = s.y + 70
            for name, recs in items:
                if name:
                    s.text(x + 36, y + 32, name, 28, True)
                    y += 40
                for piece in wrapped(recs, int(inner / (26 * 0.56))):
                    if piece.endswith("origin ai."):
                        s.rich(x + 36, y + 30, [(piece[:-3], "grey"), ("ai", "teal"), (".", "grey")], 26)
                    else:
                        s.text(x + 36, y + 30, piece, 26, False, "grey")
                    y += 36
                y += 12
        s.y += h + gap
    s.text(W / 2, s.y + 26, "Trove also reads zips of these files.", 28, True, "grey", "middle")
    s.y += 50
    for x in (W * 0.25, W * 0.5, W * 0.75):
        s.arrow(x, s.y, x, s.y + 54)
    s.y += 70
    h = 250
    s.add(f'<rect x="{M}" y="{s.y}" width="{W - 2 * M}" height="{h}" rx="16" fill="{s.c("panel")}"'
          f' stroke="{s.c("amber")}" stroke-width="4"/>')
    mark = (ROOT / "docs/brand/trove-mark.svg").read_text()
    rects = "".join(re.findall(r"<rect [^>]*></rect>", mark))
    s.add(f'<g transform="translate({M + 44} {s.y + 52}) scale(12)" shape-rendering="crispEdges">{rects}</g>')
    tx = M + 44 + 16 * 12 + 44
    s.text(tx, s.y + 84, "<name>.loot/", 34, True, "ink", mono=True)
    s.text(tx, s.y + 130, "Each engagement keeps these record types", 26, False, "grey")
    for k, piece in enumerate(wrapped(RECORD_TYPES, int((W - M - 40 - tx) / (26 * 0.56)))):
        s.text(tx, s.y + 172 + k * 36, piece, 26, True, "bronze")
    s.y += h


def status(s, r):
    w = W - 2 * M
    rows = [
        ("A parser sets ", "confirmed or failed", "tool", "$ loot find --type finding --where host=castelblack",
         field_lines(r["tool_finding"], "status")),
        ("A finding the agent reads from a note starts ", "open", "ai", "$ loot find 'Upload page' --type finding",
         field_lines(r["ai_finding"], "status")),
    ]
    for lead, what, origin, title, lines in rows:
        s.rich(M, s.y + 34, [(lead, None), (what, ORIGIN[origin])], 30, True)
        s.pill(W - M, s.y + 2, origin, ORIGIN[origin], "end")
        s.y += 62
        s.y += s.term(M, s.y, w, title, lines, [(f"[{origin},", "t_gold" if origin == "tool" else "t_teal")],
                      indent=14) + 36
    s.rich(M, s.y + 34, [("You set any status with ", None), ("loot set", "plum")], 30, True)
    s.pill(W - M, s.y + 2, "you", "plum", "end")
    s.y += 62
    you = field_lines(r["you_finding"], "status")[-1]
    decision = re.search(r"decisions/\S+?\.txt", you).group(0)
    short = decision[:40] + "..." + decision[-14:]
    lines = [f"$ loot set {r['finding_id']} status=confirmed", r["set"].strip(),
             "$ loot find 'Upload page' --type finding", "  ...", you.replace(decision, short)]
    s.y += s.term(M, s.y, w, "", lines, [("[you,", "t_plum"), ("(origin you)", "t_plum")], indent=14)


DIAGRAMS = {"merge": merge, "quotes": quotes, "parser-agent": parser_agent,
            "import-order": import_order, "tool-map": tool_map, "finding-status": status}


def build():
    r = runs()
    files = {}
    for name, draw in DIAGRAMS.items():
        for theme in THEMES:
            s = Svg(theme)
            draw(s, r)
            files[OUT / f"{name}-{theme}.svg"] = s.render()
    return files


def main(argv):
    files = build()
    if "--check" in argv:
        stale = [p.name for p, text in files.items() if not p.exists() or p.read_text() != text]
        for name in stale:
            print(f"out of date: {name}")
        return 1 if stale else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        path.write_text(text)
    print(f"wrote {len(files)} files to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
