import unittest

from lootlib import parsers
from tests import FIXTURES

EXPECTED = {
    "creds": "creds", "hydra": "hydra", "masscan": "masscan", "naabu": "naabu", "netexec": "netexec", "nuclei": "nuclei",
    "nmap/nmap-grepable.gnmap": "nmap-text",
    "nmap/nmap-normal.nmap": "nmap-text", "nmap/naabu-basic.gnmap": "nmap-text",
    "nmap/naabu-basic.xml": "nmap", "nmap/masscan-basic.gnmap": "nmap-text", "nmap/nmap-utf8.nmap": "nmap-text",
    "kerbrute/kerbrute-o-vale.txt": "kerbrute", "kerbrute/kerbrute-spray-vale.txt": "kerbrute",
    "kerbrute/kerbrute-userenum-vale.txt": ["kerbrute", "creds"],
    "freeform/tool-scratch.log": "netexec", "users": None, "freeform/client-email.txt": None,
}


class Routing(unittest.TestCase):
    """Each fixture is claimed by exactly the parser meant for it, or by none; a list names several in sniff order."""

    def test_each_fixture_is_claimed_by_one_parser_or_none(self):
        for rel, want in EXPECTED.items():
            path = FIXTURES / rel
            for f in sorted(path.iterdir()) if path.is_dir() else [path]:
                claimed = [p.NAME for p in parsers.registry() if p.sniff(f.read_bytes())]
                self.assertEqual(claimed, want if isinstance(want, list) else [want] if want else [], f.name)
