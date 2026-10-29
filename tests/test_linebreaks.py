import re
import unittest

from lootlib import parsers, records
from lootlib.parsers import Input, split_lines
from lootlib.prov import TOOL, cite
from tests import CORPUS, FIXTURES

FIXTURE_SETS = {
    "creds": sorted((FIXTURES / "creds").iterdir()),
    "netexec": sorted((FIXTURES / "netexec").iterdir()),
    "nmap-text": sorted((FIXTURES / "nmap").glob("*.*nmap")),
    "naabu": sorted((FIXTURES / "naabu").iterdir()),
    "masscan": sorted((FIXTURES / "masscan").iterdir()),
    "users": sorted((FIXTURES / "users").iterdir()),
    "certipy": sorted((CORPUS / "adcs").glob("*.txt")),
}
BREAKS = ("\x85", "\u2028", "\x0c")
# Every value here is an address or part of a NetNTLM response, which no break character can be inside.
NO_FREE_VALUE = {"Responder-Session.log"}
# A raw control character is not valid JSON, so a JSON line never holds a raw \x0c.
JSON_BREAKS = ("\x85", "\u2028")


def _known():
    """What the hashcat files and certipy's findings need held before they say anything about a value."""
    known = {}
    for path in [*FIXTURE_SETS["creds"], *FIXTURE_SETS["netexec"]]:
        if not path.name.startswith("hashcat"):
            for rec in parsers.by_name("netexec" if "nxc" in path.name else "creds").parse(
                    Input("sha256:k", path.read_bytes(), "k")):
                rec["id"] = records.make_id(rec)
                known.setdefault(rec["id"], rec)
    hashes = {h for path in FIXTURE_SETS["creds"] if path.name.startswith("hashcat")
              for h in re.findall(r"^([0-9a-f]{32}):", path.read_text(), re.MULTILINE)}
    for i, nt in enumerate(sorted(hashes)):
        cred = records.new("credential")
        for name, value in (("principal", f"held{i}"), ("secret_hash", nt), ("hash_type", "ntlm")):
            records.set_field(cred, name, value, cite("sha256:k", value.encode(), 0, len(value), TOOL))
        cred["id"] = records.make_id(cred)
        known[cred["id"]] = cred
    dns = {d for path in FIXTURE_SETS["certipy"] for d in re.findall(r"DNS Name +: (\S+)", path.read_text())}
    for i, name in enumerate(sorted(dns)):
        host = records.new("host", ip=f"10.0.0.{i}", hostnames=[name])
        host["id"] = records.make_id(host)
        known[host["id"]] = host
    return known


def _without(obj, char):
    if isinstance(obj, str):
        return obj.replace(char, "")
    if isinstance(obj, list):
        return [_without(o, char) for o in obj]
    if isinstance(obj, dict):
        if "span" in obj and "quote" in obj:
            return _without(obj["quote"], char)
        return {k: _without(v, char) for k, v in obj.items() if k != "id"}
    return obj


class LineBreaks(unittest.TestCase):
    """A character ``str.splitlines`` breaks at, inside a value, leaves every line whole: records,
    unread lines and notices are as before except for the character itself."""

    @classmethod
    def setUpClass(cls):
        cls.known = _known()

    def parse(self, name, data):
        raw = Input("sha256:x", data, "f", known=dict(self.known))
        return [parsers.by_name(name).parse(raw), raw.unread, raw.notices]

    def places(self, before, data):
        """Byte offsets inside each value cited in ``data``, then one character before the end of each
        line that is read or kept unread; a break in a line the parser skips would prove nothing."""
        spans = [ref["span"] for rec in before[0] for refs in rec["prov"].values()
                 for ref in (refs if isinstance(refs, list) else [refs]) if ref["blob"] == "sha256:x"]
        for start, end in spans:
            value = data[start:end].decode("utf-8")
            if len(value) >= 2:
                yield start + len(value[:len(value) // 2].encode("utf-8"))
        for line, at in split_lines(data.decode("utf-8")):
            end = at + len(line.encode("utf-8"))
            if len(line.strip()) >= 2 and (line in before[1] or any(at <= s < end for s, _ in spans)):
                yield at + len(line.rstrip()[:-1].encode("utf-8"))

    def test_a_break_inside_a_value_is_part_of_the_value(self):
        for name, paths in FIXTURE_SETS.items():
            for path in (p for p in paths if p.name not in NO_FREE_VALUE):
                data = path.read_bytes()
                before = self.parse(name, data)
                for char in JSON_BREAKS if path.suffix in (".json", ".ndjson") else BREAKS:
                    with self.subTest(fixture=path.name, char=repr(char)):
                        whole = next((at for at in dict.fromkeys(self.places(before, data))
                                      if _without(self.parse(name, data[:at] + char.encode("utf-8") + data[at:]),
                                                  char) == _without(before, "")), None)
                        self.assertIsNotNone(whole, "no value took the character without the file reading differently")
